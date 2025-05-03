# COS583 Project

### Implementation of Pre-Quantum Cryptography Algorithms
- [x] AES-256
- [x] DH-2048/4096
- [x] RSA-2048/4096
- [x] ECC-P256

### Implementation of Post-Quantum Crytography
- [x] ML-KEM
- [x] ML-DSA
- [x] SLH-DSA

### Encryption Time Analysis
- [x] AES-256
- [x] DH-2048/4096
- [x] RSA-2048/4096
- [x] ECC-P256
- [x] ML-KEM
- [x] ML-DSA
- [x] SLH-DSA

### Key Size Metrics (Bytes)
- [x] AES-256
- [x] DH-2048/4096
- [x] RSA-2048/4096
- [x] ECC-P256
- [x] ML-KEM
- [x] ML-DSA
- [x] SLH-DSA

### Network Metrics
- [x] AES-256
- [x] DH-2048/4096
- [x] RSA-2048/4096
- [x] ECC-P256
- [x] ML-KEM
- [x] ML-DSA
- [x] SLH-DSA

## How to run this on your local machine

Follow the steps below to set up and run this project locally:

### Prerequisites
Ensure you have the following installed on your machine:
- **Python 3.11.4**: Python 3 version which is being used for our project

### Installation Steps
1. **Clone the Repository**
    Open your terminal and run the following commands:

    ```
    cd desired-project-destination
    git clone --recurse-submodules https://github.com/Ernie5/COS583_Final_Project
    cd COS583_Final_Project
    ```

2. **Create a Virtual Environment**
    Run the following command to create your own virtual environment for this project
    ```
    python -m venv .
    source bin/activate
    ```


3. **Install Dependencies**  
   Install `cmake` from [https://cmake.org/download/](https://cmake.org/download/).

    a. Install Python requirements:

        ```
        pip install -r requirements.txt
        cd liboqs-python
        pip install .
        ```

    b. (MacOS Only) Manual Installation of liboqs and liboqs-python:
    
        ```
        brew install cmake ninja openssl
        python3 --version
        git --version
        brew install python git

        # Clone liboqs repo

        git clone --depth=1 [https://github.com/open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs)

        # Configure the build

        cmake -S liboqs -B liboqs/build -DBUILD\_SHARED\_LIBS=ON

        # Build using all available cores

        cmake --build liboqs/build --parallel 8

        # Install it (may prompt for password)

        sudo cmake --build liboqs/build --target install

        # Set dynamic library path

        export DYLD\_LIBRARY\_PATH=/usr/local/lib:\$DYLD\_LIBRARY\_PATH

        # Create and activate a virtual environment

        python3 -m venv venv
        source venv/bin/activate

        # Upgrade pip and install packaging tools

        python3 -m ensurepip --upgrade

        # Clone the Python wrapper

        git clone --depth=1 [https://github.com/open-quantum-safe/liboqs-python](https://github.com/open-quantum-safe/liboqs-python)
        cd liboqs-python

        # Optional: Update `pyproject.toml` to use version 0.13.0 if needed

        # (Change `liboqs` version from 0.12.0 to 0.13.0 inside the file)

        # Install the wrapper into your venv

        pip install .

        ```


4. **Run the Project Web App**
    Use the following commands to run the application on your local machine
    
    From the main project directory
    ```
    cd demo
    python app.py
    ```

5. **Running the Performance Tests**
    Use the following commands to run the tests from your local machine

    From the main project directory
    
    ```
    cd testing
    python test.py
    ```
    
    This test will run all of the tests at once however if one test appears to fail or not run properly, you can run the tests individually with the following commands.

    ```
    python aes_test.py
    python dh_test.py
    python ecc_test.py
    python rsa_test.py
    python ml_kem_test.py
    python ml_dsa_test.py
    python slh_dsa_test.py
    ```