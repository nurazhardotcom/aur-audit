#!/usr/bin/env bb
(ns aur-monitor
  (:require [clojure.string :as str]
            [babashka.fs :as fs]
            [clojure.java.shell :refer [sh]]))

;; Load the auditor namespace rules directly.
;; FILENAME FIX: previously referenced "aur-audit.clj" (non-existent); correct
;; filename on disk is "aur_audit.clj" per Clojure convention.
(load-file "aur_audit.clj")

(defn colorize [color text]
  (try
    (aur-audit/colorize color text)
    (catch Exception _
      (str text))))

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

(defn fetch-latest-packages []
  (println (colorize :cyan "Fetching AUR updates RSS feed…"))
  (try
    (let [res (sh "curl" "-s" "--max-time" "15" "https://aur.archlinux.org/rss/")
          xml (:out res)]
      (if (str/blank? xml)
        (do (println (colorize :red "Failed to fetch RSS: empty response")) [])
        (let [matches (re-seq #"<item>\s*<title>([^<]+)</title>" xml)
              pkg-names (map second matches)]
          (vec pkg-names))))
    (catch Exception e
      (println (colorize :red (str "Error fetching RSS feed: " (.getMessage e))))
      [])))

(defn filter-against-blacklist [pkgs blacklist]
  (let [hits (filter #(contains? blacklist (str %)) pkgs)]
    (when (seq hits)
      (println (colorize :red (str "  Blacklist pre-filter blocked: " (str/join ", " hits)))))
    (vec (remove #(contains? blacklist (str %)) pkgs))))

(defn scan-package [pkg-name]
  (let [temp-dir (fs/create-temp-dir {:prefix (str "aur-monitor-" pkg-name "-")})
        clone-url (str "https://aur.archlinux.org/" pkg-name ".git")]
    (println (colorize :bold (str "\n=== Scanning Package: " pkg-name " ===")))
    (try
      (let [git-res (sh "git" "clone" "--depth" "1" clone-url (str temp-dir))]
        (if (zero? (:exit git-res))
          (let [findings (aur-audit/audit-directory (str temp-dir))
                critical-high (filter #(or (= (:level %) :critical) (= (:level %) :high)) findings)]
            (if (empty? findings)
              (println (colorize :green (str "✓ " pkg-name " is clean.")))
              (do
                (aur-audit/print-findings findings)
                (when (not-empty critical-high)
                  (println (colorize :bold (colorize :red (str "⚠ SECURITY ALERT: Malicious indicators found in " pkg-name "!"))))))))
          (println (colorize :red (str "Failed to clone package " pkg-name ": " (:err git-res))))))
      (catch Exception e
        (println (colorize :red (str "Error scanning package " pkg-name ": " (.getMessage e)))))
      (finally
        (fs/delete-tree temp-dir)))))

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
    (if (empty? filtered-pkgs)
      (println (colorize :yellow "No packages remaining after blacklist filter."))
      (do
        (when-not json-mode
          (println (colorize :cyan (str "Auditing " (count filtered-pkgs) " of " (count raw-pkgs) " recent updates (blacklist pre-filter applied)."))))
        (doseq [pkg filtered-pkgs]
          (scan-package pkg)
          (swap! results conj {:package (str pkg)})
          (println "\n" (colorize :bold (colorize :green "=== Threat Scan Complete ===")))))
    (when json-mode
      (println (aur-audit/json-str
                {:version "1.1.0"
                 :blacklist-count (count blacklist)
                 :raw-count (count raw-pkgs)
                 :filtered-count (count filtered-pkgs)
                 :scanned (mapv :package @results)})))))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
