<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false displayMessage=false; section>
    <#if section = "header">
        <span class="w3auth-title">Web3 Authentication</span>
    <#elseif section = "form">
        <!-- Load Fonts -->
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        
        <style>
            :root {
                --bg-gradient: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
                --glass-bg: rgba(30, 41, 59, 0.45);
                --glass-border: rgba(255, 255, 255, 0.08);
                --glass-glow: rgba(99, 102, 241, 0.15);
                --text-primary: #f8fafc;
                --text-secondary: #94a3b8;
                --accent-eth: #6366f1;
                --accent-eth-hover: #4f46e5;
                --accent-sol: #14f195;
                --accent-sol-hover: #10c87b;
                --error-color: #ef4444;
            }

            .w3auth-card {
                font-family: 'Inter', sans-serif;
                background: var(--glass-bg);
                border: 1px solid var(--glass-border);
                box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37), inset 0 0 12px var(--glass-glow);
                backdrop-filter: blur(16px);
                -webkit-backdrop-filter: blur(16px);
                border-radius: 16px;
                padding: 2.5rem 2rem;
                text-align: center;
                max-width: 420px;
                margin: 2rem auto;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }

            .w3auth-card:hover {
                border-color: rgba(99, 102, 241, 0.3);
                box-shadow: 0 12px 40px 0 rgba(0, 0, 0, 0.45), inset 0 0 18px rgba(99, 102, 241, 0.25);
            }

            .w3auth-title {
                font-size: 1.5rem;
                font-weight: 700;
                color: var(--text-primary);
                letter-spacing: -0.025em;
                margin-bottom: 0.5rem;
                display: block;
            }

            .w3auth-subtitle {
                font-size: 0.875rem;
                color: var(--text-secondary);
                margin-bottom: 2rem;
                display: block;
            }

            .w3auth-btn {
                width: 100%;
                padding: 0.875rem 1.25rem;
                margin-bottom: 1rem;
                border-radius: 10px;
                border: 1px solid transparent;
                font-weight: 600;
                font-size: 0.95rem;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 0.75rem;
                transition: all 0.2s ease-in-out;
            }

            .w3auth-btn-eth {
                background: linear-gradient(135deg, var(--accent-eth) 0%, #4338ca 100%);
                color: #ffffff;
                box-shadow: 0 4px 12px rgba(99, 102, 241, 0.25);
            }

            .w3auth-btn-eth:hover {
                background: linear-gradient(135deg, var(--accent-eth-hover) 0%, #3730a3 100%);
                transform: translateY(-2px);
                box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
            }

            .w3auth-btn-sol {
                background: linear-gradient(135deg, #101010 0%, #1a1a1a 100%);
                color: var(--accent-sol);
                border: 1px solid rgba(20, 241, 149, 0.3);
                box-shadow: 0 4px 12px rgba(20, 241, 149, 0.1);
            }

            .w3auth-btn-sol:hover {
                background: linear-gradient(135deg, #151515 0%, #222222 100%);
                border-color: var(--accent-sol);
                transform: translateY(-2px);
                box-shadow: 0 6px 16px rgba(20, 241, 149, 0.2);
            }

            .w3auth-icon {
                width: 20px;
                height: 20px;
                display: block;
            }

            .w3auth-status {
                margin-top: 1.5rem;
                font-size: 0.85rem;
                color: var(--text-secondary);
                min-height: 20px;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 0.5rem;
            }

            .w3auth-spinner {
                width: 14px;
                height: 14px;
                border: 2px solid var(--text-secondary);
                border-top-color: transparent;
                border-radius: 50%;
                animation: spin 0.8s linear infinite;
                display: none;
            }

            @keyframes spin {
                to { transform: rotate(360deg); }
            }

            .w3auth-divider {
                display: flex;
                align-items: center;
                text-align: center;
                color: var(--text-secondary);
                font-size: 0.75rem;
                margin: 1.5rem 0;
            }

            .w3auth-divider::before, .w3auth-divider::after {
                content: '';
                flex: 1;
                border-bottom: 1px solid var(--glass-border);
            }

            .w3auth-divider:not(:empty)::before { margin-right: 1em; }
            .w3auth-divider:not(:empty)::after { margin-left: 1em; }

            .w3auth-alert-error {
                background: rgba(239, 68, 68, 0.15);
                border: 1px solid rgba(239, 68, 68, 0.25);
                color: #fca5a5;
                font-size: 0.85rem;
                padding: 0.75rem;
                border-radius: 8px;
                margin-bottom: 1.5rem;
                text-align: left;
            }
        </style>

        <div class="w3auth-card">
            <span class="w3auth-title">Verify Wallet Identity</span>
            <span class="w3auth-subtitle">Select a namespace to prove ownership and log in</span>

            <!-- Error Banner -->
            <div id="w3auth-error-banner" class="w3auth-alert-error" style="display: <#if message?? && message.summary??>block<#else>none</#if>;">
                <span id="w3auth-error-text"><#if message?? && message.summary??>${message.summary}</#if></span>
            </div>

            <!-- Login form submitted back to Keycloak -->
            <form id="w3auth-form" action="${url.loginAction}" method="post" style="display: none;">
                <input type="hidden" name="accountId" id="form-accountId">
                <input type="hidden" name="messageHex" id="form-message-hex">
                <input type="hidden" name="signature" id="form-signature">
            </form>

            <!-- Buttons -->
            <button class="w3auth-btn w3auth-btn-eth" onclick="loginEthereum()">
                <!-- Ethereum Icon -->
                <svg class="w3auth-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M11.986 3L11.773 3.72V15.3l.213.21 5.438-3.21L11.986 3z" fill="#EAEAEA"/>
                    <path d="M11.986 3L6.55 12.3l5.436 3.21V3z" fill="#C2C2C2"/>
                    <path d="M11.986 16.59l-.12.146V21l.12.35 5.442-7.65-5.442 6.3z" fill="#EAEAEA"/>
                    <path d="M11.986 21.35V16.59L6.55 13.7l5.436 7.65z" fill="#C2C2C2"/>
                    <path d="M11.986 15.3l5.438-3.21-5.438-2.43V15.3z" fill="#F0F0F0"/>
                    <path d="M6.55 12.09l5.436 3.21V9.66l-5.436 2.43z" fill="#D5D5D5"/>
                </svg>
                Sign-In with Ethereum
            </button>

            <button class="w3auth-btn w3auth-btn-sol" onclick="loginSolana()">
                <!-- Solana Icon -->
                <svg class="w3auth-icon" viewBox="0 0 380 380" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M59.3 277.5h261.5c4.7 0 9.2-2.1 12.2-5.7l17.7-21.2c4.1-4.9.6-12.2-5.8-12.2H83.4c-4.7 0-9.2 2.1-12.2 5.7l-17.7 21.2c-4.1 4.9-.6 12.2 5.8 12.2z" fill="url(#sol-g1)"/>
                    <path d="M320.8 102.5H59.3c-4.7 0-9.2 2.1-12.2 5.7L29.4 129.4c-4.1 4.9-.6 12.2 5.8 12.2h261.5c4.7 0 9.2-2.1 12.2-5.7l17.7-21.2c4.1-4.9.6-12.2-5.8-12.2z" fill="url(#sol-g2)"/>
                    <path d="M59.3 190H320.8c4.7 0 9.2-2.1 12.2-5.7l17.7-21.2c4.1-4.9.6-12.2-5.8-12.2H59.3c-4.7 0-9.2 2.1-12.2 5.7L29.4 177.8c-4.1 4.9-.6 12.2 5.8 12.2z" fill="url(#sol-g3)"/>
                    <defs>
                        <linearGradient id="sol-g1" x1="59.3" y1="250.7" x2="351.2" y2="250.7" gradientUnits="userSpaceOnUse">
                            <stop stop-color="#00FFA3"/>
                            <stop offset="1" stop-color="#DC1FFF"/>
                        </linearGradient>
                        <linearGradient id="sol-g2" x1="29.4" y1="120.9" x2="320.8" y2="120.9" gradientUnits="userSpaceOnUse">
                            <stop stop-color="#00FFA3"/>
                            <stop offset="1" stop-color="#DC1FFF"/>
                        </linearGradient>
                        <linearGradient id="sol-g3" x1="29.4" y1="165.6" x2="351.2" y2="165.6" gradientUnits="userSpaceOnUse">
                            <stop stop-color="#00FFA3"/>
                            <stop offset="1" stop-color="#DC1FFF"/>
                        </linearGradient>
                    </defs>
                </svg>
                Sign-In with Solana
            </button>

            <div class="w3auth-divider">or</div>

            <a href="${url.loginRestartFlowUrl}" class="w3auth-subtitle" style="text-decoration: none; margin-bottom: 0;">
                Return to standard login
            </a>

            <!-- Status Indicator -->
            <div class="w3auth-status">
                <div id="w3auth-spinner" class="w3auth-spinner"></div>
                <span id="w3auth-status-text">Ready to connect</span>
            </div>
        </div>

        <!-- Script Logic -->
        <script>
            const nonce = "${nonce}";
            const domain = "${expectedDomain}";
            const uri = "${expectedUri}";

            function setStatus(text, loading = false) {
                document.getElementById('w3auth-status-text').innerText = text;
                document.getElementById('w3auth-spinner').style.display = loading ? 'block' : 'none';
            }

            function setError(text) {
                document.getElementById('w3auth-error-banner').style.display = 'block';
                document.getElementById('w3auth-error-text').innerText = text;
                setStatus('Verification failed');
            }

            function clearError() {
                document.getElementById('w3auth-error-banner').style.display = 'none';
            }

            async function loginEthereum() {
                clearError();
                if (!window.ethereum) {
                    setError('No Ethereum wallet extension detected.');
                    return;
                }
                
                try {
                    setStatus('Connecting wallet...', true);
                    const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
                    const address = accounts[0];
                    
                    setStatus('Detecting chain ID...', true);
                    const chainIdHex = await window.ethereum.request({ method: 'eth_chainId' });
                    const chainIdDec = parseInt(chainIdHex, 16).toString();
                    
                    setStatus('Signing authentication challenge...', true);
                    
                    const issuedAt = new Date().toISOString();
                    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString(); // 5 min expiry
                    
                    // Construct SIWE format string exactly matching the SiweMessageParser specification
                    const message = 
                        domain + " wants you to sign in with your Ethereum account:\n" +
                        address + "\n\n" +
                        "Sign in to Keycloak.\n\n" +
                        "URI: " + uri + "\n" +
                        "Version: 1\n" +
                        "Chain ID: " + chainIdDec + "\n" +
                        "Nonce: " + nonce + "\n" +
                        "Issued At: " + issuedAt + "\n" +
                        "Expiration Time: " + expiresAt;
                        
                    // Hex-encode the exact UTF-8 bytes once: MetaMask signs these bytes (personal_sign),
                    // and we transport the SAME hex to the server. Sending plaintext instead would let
                    // the form's url-encoded serializer rewrite "\n" -> "\r\n", corrupting the signed
                    // bytes and breaking recovery. The server hex-decodes back to these exact bytes.
                    const hexMessage = "0x" + Array.from(new TextEncoder().encode(message))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join('');

                    const signature = await window.ethereum.request({
                        method: 'personal_sign',
                        params: [hexMessage, address]
                    });

                    setStatus('Submitting credentials...', true);
                    document.getElementById('form-accountId').value = "eip155:" + chainIdDec + ":" + address;
                    document.getElementById('form-message-hex').value = hexMessage;
                    document.getElementById('form-signature').value = signature;
                    document.getElementById('w3auth-form').submit();
                    
                } catch (err) {
                    console.error(err);
                    setError(err.message || 'Signature request rejected or failed.');
                }
            }

            async function loginSolana() {
                clearError();
                const isPhantom = window.solana && window.solana.isPhantom;
                if (!window.solana || !isPhantom) {
                    setError('Phantom or compatible Solana wallet not found.');
                    return;
                }
                
                try {
                    setStatus('Connecting Solana wallet...', true);
                    const resp = await window.solana.connect();
                    const address = resp.publicKey.toString();
                    
                    setStatus('Signing authentication challenge...', true);
                    
                    const issuedAt = new Date().toISOString();
                    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
                    
                    // Construct SIWS format string matching the SiwsMessageParser specification
                    // Solana default chain reference in CaipAccountId maps via SolanaCluster clusterName/genesisHash
                    const message = 
                        domain + " wants you to sign in with your Solana account:\n" +
                        address + "\n\n" +
                        "Sign in to Keycloak.\n\n" +
                        "URI: " + uri + "\n" +
                        "Version: 1\n" +
                        "Chain ID: mainnet\n" +
                        "Nonce: " + nonce + "\n" +
                        "Issued At: " + issuedAt + "\n" +
                        "Expiration Time: " + expiresAt;
                        
                    const encodedMessage = new TextEncoder().encode(message);
                    const signedMessage = await window.solana.signMessage(encodedMessage, "utf8");

                    // Transport the exact signed bytes as hex — same reason as the Ethereum path:
                    // plaintext through the form would be "\n" -> "\r\n" normalized and no longer
                    // match the bytes Phantom signed. The server hex-decodes back to these bytes.
                    const hexMessage = "0x" + Array.from(encodedMessage)
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join('');

                    // Signature is Uint8Array; convert to Hex for universal reliability.
                    // SolanaSignatureVerifier.verify accepts both Hex and Base58.
                    const signatureHex = Array.from(signedMessage.signature)
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join('');

                    setStatus('Submitting credentials...', true);
                    // Use 'mainnet' as default Solana chain context
                    document.getElementById('form-accountId').value = "solana:mainnet:" + address;
                    document.getElementById('form-message-hex').value = hexMessage;
                    document.getElementById('form-signature').value = signatureHex;
                    document.getElementById('w3auth-form').submit();
                    
                } catch (err) {
                    console.error(err);
                    setError(err.message || 'Signature request rejected or failed.');
                }
            }
        </script>
    </#if>
</@layout.registrationLayout>
