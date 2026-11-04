apt update && apt install -y curl gnupg git
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null
apt update && apt install -y gh

git config --global user.name "Lanmess Builder"
git config --global user.email "builder@lanmess.local"

gh auth login

cd /root/termux-app
git init
git add .
git commit -m "Initial commit"
gh repo create lanmess-app --public --source=. --remote=origin --push

mkdir -p .github/workflows
cat << 'EOF' > .github/workflows/build-apk.yml
name: Build Android APK

on:
  push:
    branches: [ main, master ]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Set up JDK 17
      uses: actions/setup-java@v4
      with:
        distribution: 'temurin'
        java-version: '17'

    - name: Setup Android SDK
      uses: android-actions/setup-android@v3

    - name: Accept Android Licenses
      run: |
        yes | sdkmanager --licenses || true

    - name: Grant execute permission for gradlew
      run: chmod +x gradlew

    - name: Build Debug APK
      run: ./gradlew assembleDebug --no-daemon

    - name: Upload APK Artifact
      uses: actions/upload-artifact@v4
      with:
        name: lanmess-apk
        path: app/build/outputs/apk/debug/app-debug.apk
EOF

git add .github/workflows/build-apk.yml
git commit -m "Add GitHub Actions workflow"
git push origin main
                                                                                                                                          