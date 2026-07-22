#!/usr/bin/env bb
(ns aur-monitor
  (:require [clojure.string :as str]
            [clojure.data.xml :as xml]
            [babashka.fs :as fs]
            [clojure.java.shell :refer [sh]]))

;; Load the auditor namespace rules directly from aur_audit.clj.
(load-file "aur_audit.clj")

;; ---------------------------------------------------------------------------
(defn colorize [color text]
  (try (aur-audit/colorize color text)
       (catch Exception _ (str text))))

;; ---------------------------------------------------------------------------
(def blacklisted-packages-url
  "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/data/campaigns/aur-infected/packages.txt")

(defn fetch-blacklist []
  (println (colorize :cyan "Fetching community AUR-malware blacklist…"))
  (try
    (let [res (sh "curl" "-fsSL" "--max-time" "10" blacklisted-packages-url)]
      (if (zero? (:exit res))
        (->> (str/split-lines (:out res))
             (remove str/blank?)
             (remove #(str/starts-with? (str %) "#"))
             set)
        (do (println (colorize :yellow "  Blacklist fetch returned non-zero; skipping pre-filter."))
            #{})))
    (catch Exception _
      (println (colorize :yellow "  Blacklist fetch failed; skipping pre-filter."))
      #{})))

;; ---------------------------------------------------------------------------
(defn- extract-item-titles [root]
  "Pull package names from every <item><title>...</title></item> element."
  (->> (xml-seq root)
       (filter #(= :item (:tag %)))
       (mapcat (fn [item]
                  (for [c (:content item)
                        :when (= :title (:tag c))]
                    (some #(when (string? %) %) (:content c)))))
       (remove str/blank?)))

(defn fetch-latest-packages []
  (println (colorize :cyan "Fetching AUR updates RSS feed…"))
  (try
    (let [res (sh "curl" "-s" "--max-time" "15" "https://aur.archlinux.org/rss/")
          body (:out res)]
      (if (str/blank? body)
        (do (println (colorize :red "Failed to fetch RSS: empty response")) [])
        (let [root (xml/parse-str body)
              pkg-names (extract-item-titles root)]
          (vec pkg-names))))
    (catch Exception e
      (println (colorize :red (str "Error fetching RSS feed: " (.getMessage e))))
      [])))

;; ---------------------------------------------------------------------------
(defn filter-against-blacklist [pkgs blacklist]
  (let [hits (filter #(contains? blacklist (str %)) pkgs)]
    (when (seq hits)
      (println (colorize :red (str "  Blacklist pre-filter blocked: " (str/join ", " hits)))))
    (vec (remove #(contains? blacklist (str %)) pkgs))))

;; ---------------------------------------------------------------------------
(defn scan-package [pkg-name]
  (let [temp-dir (fs/create-temp-dir {:prefix (str "aur-monitor-" pkg-name "-")})
        clone-url (str "https://aur.archlinux.org/" pkg-name ".git")]
    (println (colorize :bold (str "\n=== Scanning Package: " pkg-name " ===")))
    (try
      (let [git-res (sh "git" "clone" "--depth" "1" clone-url (str temp-dir))]
        (if (zero? (:exit git-res))
          (let [findings (aur-audit/audit-directory (str temp-dir))
                critical-high (filter #(or (= (:level %) :critical)
                                          (= (:level %) :high))
                                      findings)]
            (if (empty? findings)
              (println (colorize :green (str "✓ " pkg-name " is clean.")))
              (do
                (aur-audit/print-findings findings)
                (when (not-empty critical-high)
                  (println (colorize :bold
                                     (colorize :red
                                               (str "⚠ SECURITY ALERT: Malicious indicators found in "
                                                    pkg-name "!"))))))))
          (println (colorize :red (str "Failed to clone package " pkg-name ": " (:err git-res))))))
      (catch Exception e
        (println (colorize :red (str "Error scanning package " pkg-name ": " (.getMessage e)))))
      (finally (fs/delete-tree temp-dir)))))

;; ---------------------------------------------------------------------------
;; -main: rewritten for v1.1.1 hotfix. Body shape (top-to-bottom, all panels
;; paired with a closing paren on the same line or the immediate next line):
;;
;;   (let [bindings...]                                       ; +1 let
;;     (if json-mode (println (json-str {...})) ...)          ; +1 if + 1 when + 1 println + 1 json-str (?if... we'll see)
;;     ...rest...
;;     ))                                                     ; close let, defn
(defn -main [& args]
  (let [json-mode (boolean (some #(= "--json" (str %)) args))
        blacklist (fetch-blacklist)
        raw-pkgs (take 10 (fetch-latest-packages))
        filtered-pkgs (filter-against-blacklist raw-pkgs blacklist)
        results (atom [])]
    (when-not json-mode
      (println (colorize :bold (colorize :green "===========================================")))
      (println (colorize :bold (colorize :green "   AUR Real-time Security Threat Monitor   ")))
      (println (colorize :bold (colorize :green "===========================================")))
      (println (colorize :cyan (str "Auditing " (count filtered-pkgs) " of " (count raw-pkgs)
                                    " recent updates (blacklist pre-filter applied)."))))
    (if (empty? filtered-pkgs)
      (do (when-not json-mode
            (println (colorize :yellow "No packages remaining after blacklist filter."))))
      (do
        (doseq [pkg filtered-pkgs]
          (scan-package pkg)
          (swap! results conj {:package (str pkg)})
          (println "\n" (colorize :bold (colorize :green "=== Threat Scan Complete ==="))))))
    (when json-mode
      (println (aur-audit/json-str
                {                 :version "1.1.1"
                 :blacklist-count (count blacklist)
                 :raw-count (count raw-pkgs)
                 :filtered-count (count filtered-pkgs)
                 :scanned (mapv :package @results)})))))

;; ---------------------------------------------------------------------------
(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
