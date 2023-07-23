package generator

import (
    "encoding/base64"
    "helix-honeypot/model"
    "time"
)

func GenerateSecretConfig(cfg *model.Config, namespace string, honeyTokens []string, secretNames []string) map[string]interface{} {
    secrets := make([]interface{}, len(honeyTokens))

    for i, honeytoken := range honeyTokens {
        secretName := "secret-" + honeytoken
        if i < len(secretNames) {
            secretName = secretNames[i]
        }

        // Create a mock Secret structure for each honeytoken
        secret := map[string]interface{}{
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": map[string]interface{}{
                "name":      secretName,
                "namespace": namespace,
                // Subtract 3 months from the current time for the creationTimestamp
                "creationTimestamp": time.Now().AddDate(0, -3, 0).Format(time.RFC3339),
            },
            "data": map[string]interface{}{
                "token": base64.StdEncoding.EncodeToString([]byte(honeytoken)),
            },
            "type": "Opaque",
        }

        secrets[i] = secret
    }

    // Wrap the list of secrets in a Kubernetes "SecretList" structure
    secretList := map[string]interface{}{
        "apiVersion": "v1",
        "kind":       "SecretList",
        "items":      secrets,
    }

    return secretList
}
