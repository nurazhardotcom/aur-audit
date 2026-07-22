#!/usr/bin/env bb
(ns aur-audit
  (:require [clojure.string :as str]
            [clojure.java.io :as io]
            [babashka.fs :as fs]
            [clojure.java.shell :refer [sh]]))

;; --- Configuration & Rules ---

(def rules
  [{:id "NET-01"
    :level :critical
    :desc "Outbound network utilities or socket connections"
    :regex #"(?i)\b(curl|wget|nc|netcat|fetch|urllib|requests|socket)\b|/dev/tcp|/dev/udp"}
   {:id "OBF-01"
    :level :high
    :desc "Obfuscated payloads or dynamic evaluation tools"
    :regex #"(?i)\b(base64\s+-(d|-decode)|openssl\s+enc|xxd\s+-r|eval\b)"}
   {:id "EXEC-01"
    :level :high
    :desc "Direct execution of remote files/pipes"
    :regex #"(?i)\b(sh|bash|zsh|dash|ash)\s+<\s*\("}
   {:id "PERS-01"
    :level :high
    :desc "Attempts to establish persistence or enable system services"
    :regex #"(?i)(/etc/systemd/system|/etc/cron|systemctl\s+(enable|start))"}
   {:id "ENV-01"
    :level :high
    :desc "Modifications targeting user terminal profiles"
    :regex #"(?i)\.(bashrc|zshrc|profile|bash_profile)\b"}
   {:id "WRITE-01"
    :level :medium
    :desc "Writing to sensitive system folders outside packaging roots"
    :regex #"(?i)(>>|>)\s*(/etc/|/usr/|/var/|/boot/|/home/|/opt/)"}
   ;; --- 2026-06-12 AUR malicious packages incident IOCs ---
   {:id "NPM-01"
    :level :critical
    :desc "Malicious JS dependency fetched via npm/bun/yarn/pnpm in install hook"
    :regex #"(?i)\b(npm|bun|yarn|pnpm)\s+(install|add|i|exec)\b.*?\b(atomic-lockfile|js-digest|lockfile-js)\b"}
   {:id "OBF-02"
    :level :high
    :desc "Remote payload downloaded, base64-decoded, and piped into an interpreter (incident IOC pattern)"
    :regex #"(?i)\b(curl|wget)\b[^|\n]*\|\s*base64\s*-d\s*\|\s*(sh|bash|python|perl|node)\b"}
   {:id "SVC-01"
    :level :critical
    :desc "Systemd ExecStart pointing at ephemeral filesystem (incident rootkit launcher)"
    :regex #"(?i)ExecStart=\s*([\"']?)(/tmp/|/dev/shm/)"}])

;; --- Host-state checks (filesystem, services, kernel) ---

(def host-state-checks
  [{:id "HOST-BPF-01"
    :level :critical
    :desc "eBPF rootkit map pinned at /sys/fs/bpf/hidden_* (AUR incident IOC)"
    :check (fn []
             (try
               (let [entries (fs/list-dir "/sys/fs/bpf")]
                 (->> entries
                      (map (fn [p] (str (fs/file-name p))))
                      (filter #(re-find #"^hidden_" %))
                      (not-empty)))
               (catch Exception _ nil)))}
   {:id "HOST-SVC-01"
    :level :high
    :desc "Systemd unit with ExecStart targeting /tmp or /dev/shm (incident payload launcher)"
    :check (fn []
             (let [paths ["/etc/systemd/system/"
                          "/etc/systemd/user/"
                          "/usr/lib/systemd/system/"
                          "/usr/lib/systemd/user/"]
                   res (try
                         (apply sh (concat ["grep" "-rEl"
                                            "ExecStart=(/tmp/|/dev/shm/)"]
                                           paths))
                         (catch Exception _ {:exit 1 :out ""}))]
               (when (and res (zero? (:exit res)) (not (str/blank? (:out res))))
                 (str/trim (:out res)))))}])

;; --- Console Colors ---

(def ^:private tty?
  (try (and (.isTerminal *out*)
            (.isTerminal *err*))
       (catch Exception _ true)))

(defn colorize [color text]
  (if-not tty?
    (str text)
    (let [codes {:red "\u001B[31m"
                 :green "\u001B[32m"
                 :yellow "\u001B[33m"
                 :cyan "\u001B[36m"
                 :bold "\u001B[1m"
                 :reset "\u001B[0m"}]
      (str (get codes color "") text (get codes :reset "")))))

;; --- Audit Core ---

(defn analyze-line [line line-num file-name]
  (keep (fn [{:keys [id level desc regex]}]
          (when-let [match (re-find regex line)]
            {:id id
             :level level
             :desc desc
             :match match
             :line-num line-num
             :line (str/trim line)
             :file file-name}))
        rules))

(defn audit-file [file]
  (let [path (str file)
        file-name (fs/file-name file)]
    (println (colorize :cyan (str "Auditing: " file-name)))
    (if (fs/exists? file)
      (with-open [rdr (io/reader (str file))]
        (doall
         (flatten
          (map-indexed (fn [idx line]
                         (analyze-line line (inc idx) file-name))
                       (line-seq rdr)))))
      (do
        (println (colorize :red (str "File not found: " path)))
        []))))

(defn audit-directory [dir-path]
  (let [dir (fs/file dir-path)
        pkgbuild (fs/file dir "PKGBUILD")
        srcinfo (fs/file dir ".SRCINFO")
        install-files (fs/glob dir "*.install")
        all-files (concat [pkgbuild srcinfo] install-files)
        existing-files (filter fs/exists? all-files)]
    (if (empty? existing-files)
      (do
        (println (colorize :red (str "No audit targets (PKGBUILD / .SRCINFO / .install) found in " dir-path)))
        [])
      (mapcat audit-file existing-files))))

(defn host-state-findings []
  (keep (fn [{:keys [id level desc check]}]
          (let [v (try (check) (catch Exception e (str "ERROR: " (.getMessage e))))]
            (when (and v
                       (not= "" (str v))
                       (not (false? (boolean v))))
              {:id id
               :level level
               :desc desc
               :match (str v)})))
        host-state-checks))

;; --- Presentation ---

(defn print-findings [findings]
  (doseq [{:keys [id level desc match line-num line file]} findings]
    (let [level-color (case level
                        :critical :red
                        :high :red
                        :medium :yellow
                        :low :cyan)
          level-str (str "[" (str/upper-case (name level)) "]")]
      (println (colorize :bold (colorize level-color (str level-str " " id " - " desc))))
      (when (or file (some? line-num))
        (println (colorize :bold (str "  File: ")) file ":" (or line-num "-")))
      (when match
        (println "  Match:" (colorize :red (str "\"" match "\""))))
      (when line
        (println "  Line: " (colorize :yellow line))))
    (println)))

;; --- JSON output (no external deps) ---

(defn json-string [s]
  (str "\""
       (-> (str s)
           (str/replace "\\" "\\\\")
           (str/replace "\"" "\\\"")
           (str/replace "\n" "\\n")
           (str/replace "\r" "\\r")
           (str/replace "\t" "\\t"))
       "\""))

(defn json-str [v]
  (cond
    (nil? v) "null"
    (or (true? v) (false? v)) (str v)
    (string? v) (json-string v)
    (keyword? v) (json-string (name v))
    (integer? v) (str v)
    (float? v) (str v)
    (map? v) (str "{"
                  (str/join ","
                            (for [[k val] v]
                              (str (json-str (if (keyword? k) (name k) (str k)))
                                   ":" (json-str val))))
                  "}")
    (coll? v) (str "[" (str/join "," (map json-str v)) "]")
    :else (json-str (str v))))

(defn print-json [payload]
  (println (json-str payload)))

;; --- Main CLI Entry ---

(defn -main [& args]
  (let [json-mode (boolean (some #(= "--json" (str %)) args))
        no-host (boolean (some #(= "--no-host" (str %)) args))
        no-color (boolean (some #(= "--no-color" (str %)) args))
        target (or (first (remove #(str/starts-with? (str %) "--") args)) ".")]
    (when-not json-mode
      (println (colorize :bold (colorize :green "==========================================")))
      (println (colorize :bold (colorize :green "  AUR Package Security Audit · v1.1.1     ")))
      (println (colorize :bold (colorize :green "=========================================="))))
    (if (fs/exists? target)
      (let [fs-findings (if (fs/directory? target)
                          (audit-directory target)
                          (audit-file target))
            host-findings (if no-host [] (host-state-findings))
            findings (concat fs-findings host-findings)
            critical-high (filter #(or (= (:level %) :critical) (= (:level %) :high)) findings)]
        (if json-mode
          (do
            (print-json {                         :version "1.1.1"
                         :target target
                         :findings (vec findings)
                         :summary {:total (count findings)
                                   :critical-high (count critical-high)
                                   :by-level (frequencies (map :level findings))}})
            (System/exit (if (seq critical-high) 1 0)))
          (do
            (println "------------------------------------------")
            (if (empty? findings)
              (do
                (println (colorize :green "✓ Audit clean! No obvious indicators of compromise found."))
                (System/exit 0))
              (do
                (print-findings findings)
                (println (colorize :bold (str "Total Findings: " (count findings))))
                (if (not-empty critical-high)
                  (do
                    (println (colorize :red "⚠ CRITICAL/HIGH risk items found. Build aborted!"))
                    (System/exit 1))
                  (do
                    (println (colorize :yellow "⚠ Medium/Low risk items found. Review carefully."))
                    (System/exit 0))))))))
      (do
        (println (colorize :red (str "Target path does not exist: " target)))
        (println "Usage: aur-audit.clj [--json] [--no-host] [--no-color] [pkg-directory | PKGBUILD-path]")
        (System/exit 2)))))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
