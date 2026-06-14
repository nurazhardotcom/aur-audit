#!/usr/bin/env bb
(ns aur-monitor
  (:require [clojure.string :as str]
            [babashka.fs :as fs]
            [babashka.process :refer [shell]]
            [clojure.java.shell :refer [sh]]))

;; Load the auditor namespace rules directly by loading the file
(load-file "aur-audit.clj")

(defn colorize [color text]
  (let [codes {:red "\u001B[31m"
               :green "\u001B[32m"
               :yellow "\u001B[33m"
               :cyan "\u001B[36m"
               :bold "\u001B[1m"
               :reset "\u001B[0m"}]
    (str (get codes color "") text (get codes :reset ""))))

(defn fetch-latest-packages []
  (println (colorize :cyan "Fetching AUR updates RSS feed..."))
  (try
    (let [res (sh "curl" "-s" "https://aur.archlinux.org/rss/")
          xml (:out res)]
      (if (str/blank? xml)
        (do (println (colorize :red "Failed to fetch RSS: empty response")) [])
        ;; Extract package names from <item><title>PackageName</title>
        (let [matches (re-seq #"<item>\s*<title>([^<]+)</title>" xml)
              pkg-names (map second matches)]
          (vec pkg-names))))
    (catch Exception e
      (println (colorize :red (str "Error fetching RSS feed: " (.getMessage e))))
      [])))

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
  (println (colorize :bold (colorize :green "==========================================")))
  (println (colorize :bold (colorize :green "    AUR Real-time Security Threat Monitor ")))
  (println (colorize :bold (colorize :green "==========================================")))
  (let [pkgs (take 10 (fetch-latest-packages))] ; Audit the 10 most recent updates
    (if (empty? pkgs)
      (println (colorize :yellow "No packages found to scan."))
      (do
        (println (colorize :cyan (str "Identified " (count pkgs) " recent updates to audit.")))
        (doseq [pkg pkgs]
          (scan-package pkg))
        (println "\n" (colorize :bold (colorize :green "=== Threat Scan Complete ===")))))))

(when (= *file* (System/getProperty "babashka.file"))
  (apply -main *command-line-args*))
