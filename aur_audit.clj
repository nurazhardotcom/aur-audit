#!/usr/bin/env bb
(ns aur-audit
  (:require [clojure.string :as str]
            [clojure.java.io :as io]
            [babashka.fs :as fs]))

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
    :regex #"(?i)(>>|>)\s*(/etc/|/usr/|/var/|/boot/|/home/|/opt/)"}])

;; --- Console Colors ---

(defn colorize [color text]
  (let [codes {:red "\u001B[31m"
               :green "\u001B[32m"
               :yellow "\u001B[33m"
               :cyan "\u001B[36m"
               :bold "\u001B[1m"
               :reset "\u001B[0m"}]
    (str (get codes color "") text (get codes :reset ""))))

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
        install-files (fs/glob dir "*.install")
        all-files (conj (vec install-files) pkgbuild)
        existing-files (filter fs/exists? all-files)]
    (if (empty? existing-files)
      (do
        (println (colorize :red (str "No audit targets (PKGBUILD / .install) found in " dir-path)))
        [])
      (mapcat audit-file existing-files))))

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
      (println (colorize :bold (str "  File: ")) file ":" line-num)
      (println "  Match:" (colorize :red (str "\"" match "\"")))
      (println "  Line: " (colorize :yellow line))
      (println))))

;; --- Main CLI Entry ---

(defn -main [& args]
  (println (colorize :bold (colorize :green "========================================")))
  (println (colorize :bold (colorize :green "        AUR Package Security Audit      ")))
  (println (colorize :bold (colorize :green "========================================")))
  (let [target (or (first args) ".")]
    (if (fs/exists? target)
      (let [findings (if (fs/directory? target)
                       (audit-directory target)
                       (audit-file target))
            critical-high (filter #(or (= (:level %) :critical) (= (:level %) :high)) findings)]
        (println "----------------------------------------")
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
                (System/exit 0))))))
      (do
        (println (colorize :red (str "Target path does not exist: " target)))
        (println "Usage: aur-audit.clj [pkg-directory | PKGBUILD-path]")
        (System/exit 2)))))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
