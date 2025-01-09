# akamai_property.www_hipercard_com_br:
resource "akamai_property" "www_hipercard_com_br" {
    contract_id        = "ctr_C-7MYXL9"
    group_id           = "grp_25408"
    name               = "www.hipercard.com.br"
    product_id         = "prd_Fresca"
    rule_format        = "latest"
    rules              = jsonencode(
        {
            comments = <<-EOT
                Change Edge Hostname
                Case: F-CS-9005048
            EOT
            rules    = {
                name      = "default"
                options   = {
                    is_secure = true
                }
                behaviors = [
                    {
                        name    = "origin"
                        options = {
                            # cacheKeyHostname               = "ORIGIN_HOSTNAME"
                            compress                       = true
                            # customCertificateAuthorities   = [
                            #     {
                            #         canBeCA                 = true
                            #         canBeLeaf               = true
                            #         issuerRDNs              = {
                            #             C  = "US"
                            #             CN = "Amazon Root CA 1"
                            #             O  = "Amazon"
                            #         }
                            #         notAfter                = 1760832000000
                            #         notBefore               = 1445472000000
                            #         pemEncodedCert          = <<-EOT
                            #             -----BEGIN CERTIFICATE-----
                            #             MIIESTCCAzGgAwIBAgITBn+UV4WH6Kx33rJTMlu8mYtWDTANBgkqhkiG9w0BAQsF
                            #             ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
                            #             b24gUm9vdCBDQSAxMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL
                            #             MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB
                            #             IDFCMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
                            #             AoIBAQDCThZn3c68asg3Wuw6MLAd5tES6BIoSMzoKcG5blPVo+sDORrMd4f2AbnZ
                            #             cMzPa43j4wNxhplty6aUKk4T1qe9BOwKFjwK6zmxxLVYo7bHViXsPlJ6qOMpFge5
                            #             blDP+18x+B26A0piiQOuPkfyDyeR4xQghfj66Yo19V+emU3nazfvpFA+ROz6WoVm
                            #             B5x+F2pV8xeKNR7u6azDdU5YVX1TawprmxRC1+WsAYmz6qP+z8ArDITC2FMVy2fw
                            #             0IjKOtEXc/VfmtTFch5+AfGYMGMqqvJ6LcXiAhqG5TI+Dr0RtM88k+8XUBCeQ8IG
                            #             KuANaL7TiItKZYxK1MMuTJtV9IblAgMBAAGjggE7MIIBNzASBgNVHRMBAf8ECDAG
                            #             AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUWaRmBlKge5WSPKOUByeW
                            #             dFv5PdAwHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUH
                            #             AQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRy
                            #             dXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRy
                            #             dXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3Js
                            #             LnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBMGA1UdIAQMMAow
                            #             CAYGZ4EMAQIBMA0GCSqGSIb3DQEBCwUAA4IBAQCFkr41u3nPo4FCHOTjY3NTOVI1
                            #             59Gt/a6ZiqyJEi+752+a1U5y6iAwYfmXss2lJwJFqMp2PphKg5625kXg8kP2CN5t
                            #             6G7bMQcT8C8xDZNtYTd7WPD8UZiRKAJPBXa30/AbwuZe0GaFEQ8ugcYQgSn+IGBI
                            #             8/LwhBNTZTUVEWuCUUBVV18YtbAiPq3yXqMB48Oz+ctBWuZSkbvkNodPLamkB2g1
                            #             upRyzQ7qDn1X8nn8N8V7YJ6y68AtkHcNSRAnpTitxBKjtKPISLMVCx7i4hncxHZS
                            #             yLyKQXhw2W2Xs0qLeC1etA+jTGDK4UfLeC0SF7FSi8o5LL21L8IzApar2pR/
                            #             -----END CERTIFICATE-----
                            #         EOT
                            #         publicKey               = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwk4WZ93OvGrIN1rsOjCwHebREugSKEjM6CnBuW5T1aPrAzkazHeH9gG52XDMz2uN4+MDcYaZbcumlCpOE9anvQTsChY8Cus5scS1WKO2x1Yl7D5SeqjjKRYHuW5Qz/tfMfgdugNKYokDrj5H8g8nkeMUIIX4+umKNfVfnplN52s376RQPkTs+lqFZgecfhdqVfMXijUe7umsw3VOWFV9U2sKa5sUQtflrAGJs+qj/s/AKwyEwthTFctn8NCIyjrRF3P1X5rUxXIefgHxmDBjKqryei3F4gIahuUyPg69EbTPPJPvF1AQnkPCBirgDWi+04iLSmWMStTDLkybVfSG5QIDAQAB"
                            #         publicKeyAlgorithm      = "RSA"
                            #         publicKeyFormat         = "X.509"
                            #         selfSigned              = false
                            #         serialNumber            = "144918209630989264145272943054026349679957517"
                            #         sha1Fingerprint         = "917e732d330f9a12404f73d8bea36948b929dffc"
                            #         sigAlgName              = "SHA256WITHRSA"
                            #         subjectAlternativeNames = []
                            #         subjectCN               = "Amazon"
                            #         subjectRDNs             = {
                            #             C  = "US"
                            #             CN = "Amazon"
                            #             O  = "Amazon"
                            #             OU = "Server CA 1B"
                            #         }
                            #         version                 = 3
                            #     },
                            # ]
                            # customCertificates             = [
                            #     {
                            #         canBeCA                 = false
                            #         canBeLeaf               = true
                            #         issuerRDNs              = {
                            #             C  = "US"
                            #             CN = "Amazon RSA 2048 M02"
                            #             O  = "Amazon"
                            #         }
                            #         notAfter                = 1709596799000
                            #         notBefore               = 1675382400000
                            #         pemEncodedCert          = <<-EOT
                            #             -----BEGIN CERTIFICATE-----
                            #             MIIF4zCCBMugAwIBAgIQDhTzwJuEbKFcIiNyxBIstDANBgkqhkiG9w0BAQsFADA8
                            #             MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRwwGgYDVQQDExNBbWF6b24g
                            #             UlNBIDIwNDggTTAyMB4XDTIzMDIwMzAwMDAwMFoXDTI0MDMwNDIzNTk1OVowJjEk
                            #             MCIGA1UEAxMbaGlwZXJjYXJkLmNsb3VkLml0YXUuY29tLmJyMIIBIjANBgkqhkiG
                            #             9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsOGI27daFYr1+mSaPO7qj2fW+Fgs+3cQ2/k0
                            #             MYHUUvsSD36SHjY88M38TGT2OqTZwm9YRAkViZBqtYOeV0OCz8z0qW+/VXKTGlI7
                            #             K3S2420T3smLurRXwhQI6XRtkENpyTDAN2ca+ZqXgDzWYEG8VCe0VKuUxxKQYFag
                            #             m0XQ7hoN2CkZq1zcLdMZ+euoaDTRYhO4OUTiOzQ8Uh49RqG5f7HzhkweeyYYtmjl
                            #             zH3fgIdd7qhDHGOjej8rnu5GFZlPRgWv3g9VhmfCs4GSMbI2dbJyf4QuxeI9PNmP
                            #             UdvP4oAqFYQwgkx+CYHgW4Dvxg6VG5dHyVY584inJWxNHd3x4wIDAQABo4IC9TCC
                            #             AvEwHwYDVR0jBBgwFoAUwDFSzVpQw4J8dHHOy+mc+XrrguIwHQYDVR0OBBYEFOgr
                            #             r2tC7yLzLPXpt+loVu0xe1LiMCYGA1UdEQQfMB2CG2hpcGVyY2FyZC5jbG91ZC5p
                            #             dGF1LmNvbS5icjAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEG
                            #             CCsGAQUFBwMCMDsGA1UdHwQ0MDIwMKAuoCyGKmh0dHA6Ly9jcmwucjJtMDIuYW1h
                            #             em9udHJ1c3QuY29tL3IybTAyLmNybDATBgNVHSAEDDAKMAgGBmeBDAECATB1Bggr
                            #             BgEFBQcBAQRpMGcwLQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLnIybTAyLmFtYXpv
                            #             bnRydXN0LmNvbTA2BggrBgEFBQcwAoYqaHR0cDovL2NydC5yMm0wMi5hbWF6b250
                            #             cnVzdC5jb20vcjJtMDIuY2VyMAwGA1UdEwEB/wQCMAAwggF/BgorBgEEAdZ5AgQC
                            #             BIIBbwSCAWsBaQB2AO7N0GTV2xrOxVy3nbTNE6Iyh0Z8vOzew1FIWUZxH7WbAAAB
                            #             hhTfcoEAAAQDAEcwRQIhALGFuWD9q7emJOevtbhFfhjjXpxrX5wRzCHi70mowrh1
                            #             AiAnyN+v+FZ9xXdn/DGE+PwwuRDQAbWYXNbhABsyrpLjJwB2AHPZnokbTJZ4oCB9
                            #             R53mssYc0FFecRkqjGuAEHrBd3K1AAABhhTfcpgAAAQDAEcwRQIgBgvA5mF9+Cag
                            #             O+dgCae812H+XE/bPVGJKBRDMXs/ouACIQCtMLYatqrCGeBY5HhW9Zd4JfXEvKPW
                            #             WcJpVIukrg8Q/QB3AEiw42vapkc0D+VqAvqdMOscUgHLVt0sgdm7v6s52IRzAAAB
                            #             hhTfcmoAAAQDAEgwRgIhAL2HX+d8C6HuFC8p4jdIOW7/TtR/H6vVYsuDr+JnhIG0
                            #             AiEA2TKnPBJXRFb0Fdnf91HxpgZ3x+5VAeXlBLJuY0l3INwwDQYJKoZIhvcNAQEL
                            #             BQADggEBAI/s01poeEqjj5LQ5ifcDEpjbMfjFSKzfajJjt8G3+Otrp7FP4HMvkdU
                            #             gcig0Phzu5IlYXZgaggItmTuFQCq0KRqzwyFhxWgeut6r6C9sGSwuNH0t54izjMp
                            #             wAYXVcN8kExvfAFqD/NszyHVSjJ9sQzC5dk70LJzuAlR8Fny3HbHVnTcgg7OlLFU
                            #             mf7xg2j3VuDbEQvdCBk5hWtCGFoYwzuxvR1Ge7jGyFYvEi4xGwv4pdTrIFByMumt
                            #             FpPjrKqZ2wS2IjT9ZoMzB+2wdgiGqt7aPZfFMQ6hgEA6TuTSeC+kt+WkkaTrYwOt
                            #             nXeBb/qnIWbpLlnqAwNxpcfZKod+JCk=
                            #             -----END CERTIFICATE-----
                            #         EOT
                            #         publicKey               = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsOGI27daFYr1+mSaPO7qj2fW+Fgs+3cQ2/k0MYHUUvsSD36SHjY88M38TGT2OqTZwm9YRAkViZBqtYOeV0OCz8z0qW+/VXKTGlI7K3S2420T3smLurRXwhQI6XRtkENpyTDAN2ca+ZqXgDzWYEG8VCe0VKuUxxKQYFagm0XQ7hoN2CkZq1zcLdMZ+euoaDTRYhO4OUTiOzQ8Uh49RqG5f7HzhkweeyYYtmjlzH3fgIdd7qhDHGOjej8rnu5GFZlPRgWv3g9VhmfCs4GSMbI2dbJyf4QuxeI9PNmPUdvP4oAqFYQwgkx+CYHgW4Dvxg6VG5dHyVY584inJWxNHd3x4wIDAQAB"
                            #         publicKeyAlgorithm      = "RSA"
                            #         publicKeyFormat         = "X.509"
                            #         selfSigned              = false
                            #         serialNumber            = "18717981763630676590532216181853662388"
                            #         sha1Fingerprint         = "243508efb0a29090c539bc170eac4ed2f4db9e62"
                            #         sigAlgName              = "SHA256withRSA"
                            #         subjectAlternativeNames = [
                            #             "hipercard.cloud.itau.com.br",
                            #         ]
                            #         subjectCN               = "hipercard.cloud.itau.com.br"
                            #         subjectRDNs             = {
                            #             CN = "hipercard.cloud.itau.com.br"
                            #         }
                            #         version                 = 3
                            #     },
                            #     {
                            #         canBeCA                 = false
                            #         canBeLeaf               = true
                            #         issuerRDNs              = {
                            #             C  = "BE"
                            #             CN = "GlobalSign RSA OV SSL CA 2018"
                            #             O  = "GlobalSign nv-sa"
                            #         }
                            #         notAfter                = 1724255770000
                            #         notBefore               = 1689954971000
                            #         pemEncodedCert          = <<-EOT
                            #             -----BEGIN CERTIFICATE-----
                            #             MIIGZDCCBUygAwIBAgIMOG7OakfsfO7mkOJkMA0GCSqGSIb3DQEBCwUAMFAxCzAJ
                            #             BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSYwJAYDVQQDEx1H
                            #             bG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODAeFw0yMzA3MjExNTU2MTFaFw0y
                            #             NDA4MjExNTU2MTBaMHExCzAJBgNVBAYTAkJSMRIwEAYDVQQIEwlTQU8gUEFVTE8x
                            #             EjAQBgNVBAcTCVNBTyBQQVVMTzEbMBkGA1UEChMSSVRBVSBVTklCQU5DTyBTLkEu
                            #             MR0wGwYDVQQDExR3d3cuaGlwZXJjYXJkLmNvbS5icjCCASIwDQYJKoZIhvcNAQEB
                            #             BQADggEPADCCAQoCggEBAOxyJpC+MY2z8P4MhkoAqcg/vhe5XWFklrRO9TAAIZIl
                            #             k5rpi1wd9dtFuC7Acpr189Noh334/okwuUo9w6O6NuMUXTvTSHalWwYeCNaIl4s+
                            #             KD044zOp+DycCFasQP1VCYgBPkgBH5LmHqdPuOOLhjviDENbFYm8nS95kEwnegbx
                            #             4m7tyx0o+ANJi8QHCpdF3aMMbrWvr4DRN+Z5fxRx9FmG/sP7DLCZ8sdyPZeW/nKG
                            #             jsXmJ+29bc9yqYHNq3ipGwRLdNMk8jxrUND2xthUCgYRzPy/qMrXh6nnHx3U7q+s
                            #             cS0asfvF6eUZpxm4f5B2o1oocemVHP7uJUtC6VcAMVcCAwEAAaOCAxswggMXMA4G
                            #             A1UdDwEB/wQEAwIFoDCBjgYIKwYBBQUHAQEEgYEwfzBEBggrBgEFBQcwAoY4aHR0
                            #             cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3Nyc2FvdnNzbGNhMjAx
                            #             OC5jcnQwNwYIKwYBBQUHMAGGK2h0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dz
                            #             cnNhb3Zzc2xjYTIwMTgwVgYDVR0gBE8wTTBBBgkrBgEEAaAyARQwNDAyBggrBgEF
                            #             BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wCAYG
                            #             Z4EMAQICMAkGA1UdEwQCMAAwMQYDVR0RBCowKIIUd3d3LmhpcGVyY2FyZC5jb20u
                            #             YnKCEGhpcGVyY2FyZC5jb20uYnIwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF
                            #             BwMCMB8GA1UdIwQYMBaAFPjvf/LNeGeo3m+PJI2I8YcDArPrMB0GA1UdDgQWBBRT
                            #             k7tygYweRX2QzncxKVi89bKs+DCCAX0GCisGAQQB1nkCBAIEggFtBIIBaQFnAHUA
                            #             SLDja9qmRzQP5WoC+p0w6xxSActW3SyB2bu/qznYhHMAAAGJeSqMYQAABAMARjBE
                            #             AiAlol3DyYfimT96Pt4JzqkRNm/3rO744xKMWcOAcIGCmgIgZiGYQj6ScigZG6g7
                            #             ZbKujusg7gzPkNqDkGV4TAsTKCQAdgDuzdBk1dsazsVct520zROiModGfLzs3sNR
                            #             SFlGcR+1mwAAAYl5Ko0yAAAEAwBHMEUCIQDq31IpDJw6HLrDanwq0WaN75jFRrOY
                            #             142noGyKGZSKTAIgGHqaAi5YbAsRuokoTscfVsrqffANQ4BhU6lwWuHD5usAdgDa
                            #             tr9rP7W2Ip+bwrtca+hwkXFsu1GEhTS9pD0wSNf7qwAAAYl5Kop3AAAEAwBHMEUC
                            #             IQDT0FQlyfPHCa5ZHiaBsXEC6N71xOAz6sxTQgPdZSjXfgIgOSQmtPO6p7PxKIAC
                            #             +MW9wMSrrOSUS4JL6QJZOdGrPsswDQYJKoZIhvcNAQELBQADggEBAId1l+ofiE1Y
                            #             Iy831+1xkj2Ca2gkf4KM05htEq8cHe0FicXJz+Hd98ZERzEeaAdshuwaYK8sscx9
                            #             ml9k9yO8KorAt3G2BpWlxXODpY2Zig/CBsvY0EoRBF5IMbhYWwzZgqBF6lqXKS/T
                            #             43B3FG2a0o77L4QtBOtFId48jtje4UkS/Ikse1lXjOkIe8MoNFM1eVqp7dWNvMU4
                            #             I2J2Ab6TVA0kKURdia58+EeK1MWhxh/pIXW3eBw+ZYh5bbY28N9wOXGWX3+WqN3j
                            #             eoCtSMuncc9TUf7EqIvumQ2cNl5DSv5zcb2mDyWqYorCl2O3p6T6poA80HNDvF0T
                            #             SjKTdsLcUUM=
                            #             -----END CERTIFICATE-----
                            #         EOT
                            #         publicKey               = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7HImkL4xjbPw/gyGSgCpyD++F7ldYWSWtE71MAAhkiWTmumLXB3120W4LsBymvXz02iHffj+iTC5Sj3Do7o24xRdO9NIdqVbBh4I1oiXiz4oPTjjM6n4PJwIVqxA/VUJiAE+SAEfkuYep0+444uGO+IMQ1sVibydL3mQTCd6BvHibu3LHSj4A0mLxAcKl0Xdowxuta+vgNE35nl/FHH0WYb+w/sMsJnyx3I9l5b+coaOxeYn7b1tz3Kpgc2reKkbBEt00yTyPGtQ0PbG2FQKBhHM/L+oyteHqecfHdTur6xxLRqx+8Xp5RmnGbh/kHajWihx6ZUc/u4lS0LpVwAxVwIDAQAB"
                            #         publicKeyAlgorithm      = "RSA"
                            #         publicKeyFormat         = "X.509"
                            #         selfSigned              = false
                            #         serialNumber            = "17465117158185930654640824932"
                            #         sha1Fingerprint         = "174d805d86defa567092b4b7b35dd4c504956894"
                            #         sigAlgName              = "SHA256WITHRSA"
                            #         subjectAlternativeNames = [
                            #             "www.hipercard.com.br",
                            #             "hipercard.com.br",
                            #         ]
                            #         subjectCN               = "www.hipercard.com.br"
                            #         subjectRDNs             = {
                            #             C  = "BR"
                            #             CN = "www.hipercard.com.br"
                            #             L  = "SAO PAULO"
                            #             O  = "ITAU UNIBANCO S.A."
                            #             ST = "SAO PAULO"
                            #         }
                            #         version                 = 3
                            #     },
                            # ]
                            # customValidCnValues            = [
                            #     "{{Origin Hostname}}",
                            #     "{{Forward Host Header}}",
                            # ]
                            enableTrueClientIp             = true
                            forwardHostHeader              = "ORIGIN_HOSTNAME"
                            hostname                       = "hipercard.cloud.itau.com.br"
                            httpPort                       = 80
                            httpsPort                      = 443
                            ipVersion                      = "IPV4"
                            # minTlsVersion                  = "DYNAMIC"
                            # originCertificate              = ""
                            # originCertsToHonor             = "COMBO"
                            # originSni                      = true
                            # originType                     = "CUSTOMER"
                            ports                          = ""
                            # standardCertificateAuthorities = [
                            #     "akamai-permissive",
                            #     "THIRD_PARTY_AMAZON",
                            # ]
                            # tlsVersionTitle                = ""
                            # trueClientIpClientSetting      = false
                            trueClientIpHeader             = "True-Client-IP"
                            # useUniqueCacheKey              = false
                            # verificationMode               = "CUSTOM"
                        }
                    },
                    # {
                    #     name    = "cpCode"
                    #     options = {
                    #         value = {
                    #             cpCodeLimits = {
                    #                 currentCapacity = 13
                    #                 limit           = 200
                    #                 limitType       = "account"
                    #             }
                    #             createdDate  = 1559330921000
                    #             description  = "BR - Itau - ION - www.hipercard.com.br"
                    #             id           = 856106
                    #             name         = "BR - Itau - ION - www.hipercard.com.br"
                    #             products     = [
                    #                 "Fresca",
                    #             ]
                    #         }
                    #     }
                    # },
                    # {
                    #     name    = "sureRoute"
                    #     options = {
                    #         customMap           = "www.itau.com.br.akasrg.akamai.com"
                    #         enableCustomKey     = false
                    #         enabled             = true
                    #         forceSslForward     = true
                    #         raceStatTtl         = "1d"
                    #         srDownloadLinkTitle = ""
                    #         testObjectUrl       = "/itausrt.html"
                    #         toHostStatus        = "INCOMING_HH"
                    #         type                = "CUSTOM_MAP"
                    #     }
                    # },
                    {
                        name    = "allowPost"
                        options = {
                            allowWithoutContentLength = true
                            enabled                   = true
                        }
                    },
                    # {
                    #     name    = "report"
                    #     options = {
                    #         logAcceptLanguage = true
                    #         logCookies        = "ALL"
                    #         logCustomLogField = false
                    #         logEdgeIP         = false
                    #         logHost           = true
                    #         logReferer        = true
                    #         logUserAgent      = true
                    #         logXForwardedFor  = false
                    #     }
                    # },
                    # {
                    #     name    = "webApplicationFirewall"
                    #     options = {
                    #         firewallConfiguration = {
                    #             configId          = 3261
                    #             fileName          = "waf_portal_3261.xml"
                    #             productionStatus  = "Active"
                    #             productionVersion = 75
                    #             stagingStatus     = "Active"
                    #             stagingVersion    = 76
                    #         }
                    #     }
                    # },
                    {
                        name    = "caching"
                        options = {
                            behavior       = "MAX_AGE"
                            mustRevalidate = false
                            ttl            = "1h"
                        }
                    },
                    {
                        name    = "cacheError"
                        options = {
                            enabled       = true
                            preserveStale = true
                            ttl           = "15s"
                        }
                    },
                    {
                        name    = "removeVary"
                        options = {
                            enabled = true
                        }
                    },
                    # {
                    #     name    = "siteShield"
                    #     options = {
                    #         ssmap = {
                    #             hasMixedHosts = false
                    #             name          = "e;s217.akamaiedge.net (s217.akamaiedge.net)"
                    #             src           = "PREVIOUS_MAP"
                    #             srmap         = "www.itau.com.br.akasrg.akamai.com"
                    #             value         = "s217.akamaiedge.net"
                    #         }
                    #     }
                    # },
                    {
                        name    = "forwardRewrite"
                        options = {
                            cloudletPolicy = {
                                id   = 149875
                                name = "Hipercard_Proxy"
                            }
                            enabled        = true
                            isSharedPolicy = false
                        }
                    },
                    {
                        name    = "edgeRedirector"
                        options = {
                            cloudletPolicy = {
                                id   = 165512
                                name = "Hipercard_Redirector"
                            }
                            enabled        = true
                            isSharedPolicy = false
                        }
                    },
                    # {
                    #     name    = "datastream"
                    #     options = {
                    #         logEnabled         = true
                    #         logStreamName      = [
                    #             "16802",
                    #         ]
                    #         logStreamTitle     = ""
                    #         samplingPercentage = 100
                    #         streamType         = "LOG"
                    #     }
                    # },
                ]
                children  = [
                    {
                        behaviors           = [
                            {
                                name    = "redirect"
                                options = {
                                    destinationHostname = "SAME_AS_REQUEST"
                                    destinationPath     = "SAME_AS_REQUEST"
                                    destinationProtocol = "HTTPS"
                                    mobileDefaultChoice = "DEFAULT"
                                    queryString         = "APPEND"
                                    responseCode        = 301
                                }
                            },
                        ]
                        comments            = "Redirect to the same URL on HTTPS protocol, issuing a 301 response code (Moved Permanently). You may change the response code to 302 if needed."
                        criteria            = [
                            {
                                name    = "requestProtocol"
                                options = {
                                    value = "HTTP"
                                }
                            },
                        ]
                        criteriaMustSatisfy = "all"
                        name                = "Redirect to HTTPS"
                        options             = {}
                    },
                    {
                        behaviors           = [
                            {
                                name    = "gzipResponse"
                                options = {
                                    behavior = "ALWAYS"
                                }
                            },
                        ]
                        criteria            = [
                            {
                                name    = "contentType"
                                options = {
                                    matchCaseSensitive = false
                                    matchOperator      = "IS_ONE_OF"
                                    matchWildcard      = true
                                    values             = [
                                        "text/html*",
                                        "text/css*",
                                        "application/x-javascript*",
                                        "application/javascript",
                                        "application/x-javascript",
                                        "application/json",
                                        "application/x-json",
                                        "application/*+json",
                                        "application/*+xml",
                                        "application/text",
                                        "application/vnd.microsoft.icon",
                                        "application/vnd-ms-fontobject",
                                        "application/x-font-ttf",
                                        "application/x-font-opentype",
                                        "application/x-font-truetype",
                                        "application/xmlfont/eot",
                                        "application/xml",
                                        "font/opentype",
                                        "font/otf",
                                        "font/eot",
                                        "image/svg+xml",
                                        "image/vnd.microsoft.icon",
                                    ]
                                }
                            },
                        ]
                        criteriaMustSatisfy = "all"
                        name                = "Content Compression"
                        options             = {}
                    },
                    {
                        behaviors           = [
                            {
                                name    = "caching"
                                options = {
                                    behavior       = "MAX_AGE"
                                    mustRevalidate = false
                                    ttl            = "365d"
                                }
                            },
                            # {
                            #     name    = "prefreshCache"
                            #     options = {
                            #         enabled     = true
                            #         prefreshval = 90
                            #     }
                            # },
                            # {
                            #     name    = "prefetch"
                            #     options = {
                            #         enabled = false
                            #     }
                            # },
                            # {
                            #     name    = "prefetchable"
                            #     options = {
                            #         enabled = false
                            #     }
                            # },
                            {
                                name    = "downstreamCache"
                                options = {
                                    allowBehavior = "LESSER"
                                    behavior      = "ALLOW"
                                    sendHeaders   = "CACHE_CONTROL_AND_EXPIRES"
                                    sendPrivate   = false
                                }
                            },
                        ]
                        criteria            = [
                            {
                                name    = "fileExtension"
                                options = {
                                    matchCaseSensitive = false
                                    matchOperator      = "IS_ONE_OF"
                                    values             = [
                                        "aif",
                                        "aiff",
                                        "au",
                                        "avi",
                                        "bin",
                                        "bmp",
                                        "cab",
                                        "carb",
                                        "cct",
                                        "cdf",
                                        "class",
                                        "css",
                                        "doc",
                                        "dcr",
                                        "dtd",
                                        "exe",
                                        "flv",
                                        "gcf",
                                        "gff",
                                        "gif",
                                        "grv",
                                        "hdml",
                                        "hqx",
                                        "ico",
                                        "ini",
                                        "jpeg",
                                        "jpg",
                                        "js",
                                        "mov",
                                        "mp3",
                                        "nc",
                                        "pct",
                                        "pdf",
                                        "png",
                                        "ppc",
                                        "pws",
                                        "swa",
                                        "swf",
                                        "txt",
                                        "vbs",
                                        "w32",
                                        "wav",
                                        "wbmp",
                                        "wml",
                                        "wmlc",
                                        "wmls",
                                        "wmlsc",
                                        "xsd",
                                        "zip",
                                        "woff",
                                        "woff2",
                                        "svg",
                                    ]
                                }
                            },
                        ]
                        criteriaMustSatisfy = "all"
                        name                = "Static Content"
                        options             = {}
                    },
                    {
                        behaviors           = [
                            {
                                name    = "downstreamCache"
                                options = {
                                    behavior = "TUNNEL_ORIGIN"
                                }
                            },
                        ]
                        criteriaMustSatisfy = "all"
                        name                = "Browser caching"
                        options             = {}
                    },
                    {
                        children            = [
                            {
                                behaviors           = [
                                    {
                                        name    = "redirect"
                                        options = {
                                            destinationHostname      = "OTHER"
                                            destinationHostnameOther = "www.hipercard.com.br"
                                            destinationPath          = "SAME_AS_REQUEST"
                                            destinationProtocol      = "HTTPS"
                                            mobileDefaultChoice      = "DEFAULT"
                                            queryString              = "APPEND"
                                            responseCode             = 301
                                        }
                                    },
                                ]
                                criteria            = [
                                    {
                                        name    = "hostname"
                                        options = {
                                            matchOperator = "IS_ONE_OF"
                                            values        = [
                                                "hipercard.com.br",
                                            ]
                                        }
                                    },
                                ]
                                criteriaMustSatisfy = "all"
                                name                = "Redirect Top Level"
                                options             = {}
                            },
                            {
                                behaviors           = [
                                    {
                                        name    = "setVariable"
                                        options = {
                                            caseSensitive      = true
                                            globalSubstitution = false
                                            regex              = "index.html"
                                            replacement        = " /"
                                            transform          = "SUBSTITUTE"
                                            valueSource        = "EXPRESSION"
                                            variableName       = "PMUSER_REDIR"
                                            variableValue      = "{{builtin.AK_PATH}}"
                                        }
                                    },
                                    {
                                        name    = "redirect"
                                        options = {
                                            destinationHostname      = "OTHER"
                                            destinationHostnameOther = "www.hipercard.com.br"
                                            destinationPath          = "OTHER"
                                            destinationPathOther     = "{{user.PMUSER_REDIR}}"
                                            destinationProtocol      = "HTTPS"
                                            mobileDefaultChoice      = "DEFAULT"
                                            queryString              = "APPEND"
                                            responseCode             = 301
                                        }
                                    },
                                ]
                                criteria            = [
                                    {
                                        name    = "path"
                                        options = {
                                            matchCaseSensitive = false
                                            matchOperator      = "MATCHES_ONE_OF"
                                            normalize          = false
                                            values             = [
                                                "/cartoes/index.html",
                                                "/cartoes/ajuda/index.html",
                                            ]
                                        }
                                    },
                                ]
                                criteriaMustSatisfy = "all"
                                name                = ".html to ending /"
                                options             = {}
                            },
                        ]
                        criteriaMustSatisfy = "all"
                        name                = "Redirects"
                        options             = {}
                    },
                    {
                        children            = [
                            {
                                behaviors           = [
                                    {
                                        name    = "caching"
                                        options = {
                                            behavior       = "MAX_AGE"
                                            mustRevalidate = false
                                            ttl            = "30d"
                                        }
                                    },
                                    # {
                                    #     name    = "imageManager"
                                    #     options = {
                                    #         advanced             = false
                                    #         apiReferenceTitle    = ""
                                    #         applyBestFileType    = true
                                    #         cpCodeOriginal       = {
                                    #             cpCodeLimits = null
                                    #             createdDate  = 1600960769000
                                    #             description  = "BR - Itau - IM Prestine - www.hipercard.com.br"
                                    #             id           = 1094036
                                    #             name         = "BR - Itau - IM Prestine - www.hipercard.com.br"
                                    #             products     = [
                                    #                 "Fresca",
                                    #             ]
                                    #         }
                                    #         cpCodeTransformed    = {
                                    #             cpCodeLimits = null
                                    #             createdDate  = 1600960785000
                                    #             description  = "BR - Itau - IM Derivative - www.hipercard.com.br"
                                    #             id           = 1094038
                                    #             name         = "BR - Itau - IM Derivative - www.hipercard.com.br"
                                    #             products     = [
                                    #                 "Fresca",
                                    #             ]
                                    #         }
                                    #         enabled              = true
                                    #         policyTokenDefault   = "www_hipercard_com_br"
                                    #         resize               = true
                                    #         settingsTitle        = ""
                                    #         superCacheRegion     = "US"
                                    #         trafficTitle         = ""
                                    #         useExistingPolicySet = false
                                    #     }
                                    # },
                                ]
                                comments            = "Apply the Image and Video Manager (Images) behavior here as you would normally."
                                criteria            = [
                                    {
                                        name    = "fileExtension"
                                        options = {
                                            matchCaseSensitive = false
                                            matchOperator      = "IS_ONE_OF"
                                            values             = [
                                                "jpg",
                                                "gif",
                                                "jpeg",
                                                "png",
                                                "imviewer",
                                            ]
                                        }
                                    },
                                ]
                                criteriaMustSatisfy = "all"
                                name                = "Image and Video Manager (Images)"
                                options             = {}
                            },
                        ]
                        comments            = "The Image and Video Manager (Images) match criteria in this rule ensures IM serves derivatives as expected. This is necessary when the matches for this rule select elements that are not included when IM forwards the request within the CDN."
                        criteria            = [
                            {
                                name    = "advancedImMatch"
                                options = {
                                    matchOn       = "ANY_IM"
                                    matchOperator = "IS"
                                }
                            },
                            {
                                name    = "fileExtension"
                                options = {
                                    matchCaseSensitive = false
                                    matchOperator      = "IS_NOT_ONE_OF"
                                    values             = [
                                        "html",
                                        "pdf",
                                        "css",
                                        "js",
                                    ]
                                }
                            },
                        ]
                        criteriaMustSatisfy = "any"
                        name                = "Image and Video Manager (Images) Advanced"
                        options             = {}
                    },
                    # {
                    #     behaviors           = [
                    #         {
                    #             name    = "allowTransferEncoding"
                    #             options = {
                    #                 enabled = true
                    #             }
                    #         },
                    #         {
                    #             name    = "http2"
                    #             options = {
                    #                 enabled = ""
                    #             }
                    #         },
                    #         {
                    #             name    = "enhancedAkamaiProtocol"
                    #             options = {
                    #                 display = ""
                    #             }
                    #         },
                    #         {
                    #             name    = "prefetch"
                    #             options = {
                    #                 enabled = false
                    #             }
                    #         },
                    #     ]
                    #     criteriaMustSatisfy = "all"
                    #     name                = "Performance"
                    #     options             = {}
                    # },
                    {
                        children            = [
                            {
                                behaviors           = [
                                    {
                                        name    = "origin"
                                        options = {
                                            cacheKeyHostname               = "ORIGIN_HOSTNAME"
                                            compress                       = true
                                            customCertificateAuthorities   = []
                                            customCertificates             = []
                                            customValidCnValues            = [
                                                "{{Origin Hostname}}",
                                                "{{Forward Host Header}}",
                                            ]
                                            enableTrueClientIp             = true
                                            forwardHostHeader              = "ORIGIN_HOSTNAME"
                                            hostname                       = "hipercard.cloud.itau.com.br"
                                            httpPort                       = 80
                                            httpsPort                      = 443
                                            ipVersion                      = "IPV4"
                                            minTlsVersion                  = "DYNAMIC"
                                            originCertificate              = ""
                                            originCertsToHonor             = "COMBO"
                                            originSni                      = true
                                            originType                     = "CUSTOMER"
                                            ports                          = ""
                                            standardCertificateAuthorities = [
                                                "akamai-permissive",
                                                "THIRD_PARTY_AMAZON",
                                            ]
                                            trueClientIpClientSetting      = false
                                            trueClientIpHeader             = "True-Client-IP"
                                            useUniqueCacheKey              = false
                                            verificationMode               = "CUSTOM"
                                        }
                                    },
                                    {
                                        name    = "baseDirectory"
                                        options = {
                                            value = "/"
                                        }
                                    },
                                ]
                                criteria            = [
                                    {
                                        name    = "path"
                                        options = {
                                            matchCaseSensitive = false
                                            matchOperator      = "MATCHES_ONE_OF"
                                            normalize          = false
                                            values             = [
                                                "/assets/*",
                                            ]
                                        }
                                    },
                                ]
                                criteriaMustSatisfy = "all"
                                name                = "Arquivos estáticos"
                                options             = {}
                            },
                            {
                                behaviors           = [
                                    {
                                        name    = "rewriteUrl"
                                        options = {
                                            behavior  = "REWRITE"
                                            targetUrl = " {{builtin.AK_PATH}}/index.html"
                                        }
                                    },
                                ]
                                comments            = "todas as demais paginas de hipercard caem nessa rota, exemplo /cartoes /bandeira "
                                criteria            = [
                                    {
                                        name    = "path"
                                        options = {
                                            matchCaseSensitive = false
                                            matchOperator      = "DOES_NOT_MATCH_ONE_OF"
                                            normalize          = false
                                            values             = [
                                                "/",
                                                "/assets/*",
                                            ]
                                        }
                                    },
                                ]
                                criteriaMustSatisfy = "all"
                                name                = "Demais páginas hipercard"
                                options             = {}
                            },
                        ]
                        criteriaMustSatisfy = "all"
                        name                = "Modify Path"
                        options             = {}
                    },
                    {
                        behaviors           = [
                            {
                                name    = "allowCloudletsOrigins"
                                options = {
                                    enabled                   = true
                                    honorBaseDirectory        = true
                                    purgeOriginQueryParameter = "originId"
                                }
                            },
                        ]
                        children            = [
                            {
                                behaviors           = [
                                    {
                                        name    = "origin"
                                        options = {
                                            cacheKeyHostname               = "ORIGIN_HOSTNAME"
                                            compress                       = true
                                            customCertificateAuthorities   = []
                                            customCertificates             = [
                                                {
                                                    canBeCA                 = false
                                                    canBeLeaf               = true
                                                    issuerRDNs              = {
                                                        C  = "US"
                                                        CN = "Amazon RSA 2048 M02"
                                                        O  = "Amazon"
                                                    }
                                                    notAfter                = 1709596799000
                                                    notBefore               = 1675382400000
                                                    pemEncodedCert          = <<-EOT
                                                        -----BEGIN CERTIFICATE-----
                                                        MIIF4zCCBMugAwIBAgIQDhTzwJuEbKFcIiNyxBIstDANBgkqhkiG9w0BAQsFADA8
                                                        MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRwwGgYDVQQDExNBbWF6b24g
                                                        UlNBIDIwNDggTTAyMB4XDTIzMDIwMzAwMDAwMFoXDTI0MDMwNDIzNTk1OVowJjEk
                                                        MCIGA1UEAxMbaGlwZXJjYXJkLmNsb3VkLml0YXUuY29tLmJyMIIBIjANBgkqhkiG
                                                        9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsOGI27daFYr1+mSaPO7qj2fW+Fgs+3cQ2/k0
                                                        MYHUUvsSD36SHjY88M38TGT2OqTZwm9YRAkViZBqtYOeV0OCz8z0qW+/VXKTGlI7
                                                        K3S2420T3smLurRXwhQI6XRtkENpyTDAN2ca+ZqXgDzWYEG8VCe0VKuUxxKQYFag
                                                        m0XQ7hoN2CkZq1zcLdMZ+euoaDTRYhO4OUTiOzQ8Uh49RqG5f7HzhkweeyYYtmjl
                                                        zH3fgIdd7qhDHGOjej8rnu5GFZlPRgWv3g9VhmfCs4GSMbI2dbJyf4QuxeI9PNmP
                                                        UdvP4oAqFYQwgkx+CYHgW4Dvxg6VG5dHyVY584inJWxNHd3x4wIDAQABo4IC9TCC
                                                        AvEwHwYDVR0jBBgwFoAUwDFSzVpQw4J8dHHOy+mc+XrrguIwHQYDVR0OBBYEFOgr
                                                        r2tC7yLzLPXpt+loVu0xe1LiMCYGA1UdEQQfMB2CG2hpcGVyY2FyZC5jbG91ZC5p
                                                        dGF1LmNvbS5icjAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEG
                                                        CCsGAQUFBwMCMDsGA1UdHwQ0MDIwMKAuoCyGKmh0dHA6Ly9jcmwucjJtMDIuYW1h
                                                        em9udHJ1c3QuY29tL3IybTAyLmNybDATBgNVHSAEDDAKMAgGBmeBDAECATB1Bggr
                                                        BgEFBQcBAQRpMGcwLQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLnIybTAyLmFtYXpv
                                                        bnRydXN0LmNvbTA2BggrBgEFBQcwAoYqaHR0cDovL2NydC5yMm0wMi5hbWF6b250
                                                        cnVzdC5jb20vcjJtMDIuY2VyMAwGA1UdEwEB/wQCMAAwggF/BgorBgEEAdZ5AgQC
                                                        BIIBbwSCAWsBaQB2AO7N0GTV2xrOxVy3nbTNE6Iyh0Z8vOzew1FIWUZxH7WbAAAB
                                                        hhTfcoEAAAQDAEcwRQIhALGFuWD9q7emJOevtbhFfhjjXpxrX5wRzCHi70mowrh1
                                                        AiAnyN+v+FZ9xXdn/DGE+PwwuRDQAbWYXNbhABsyrpLjJwB2AHPZnokbTJZ4oCB9
                                                        R53mssYc0FFecRkqjGuAEHrBd3K1AAABhhTfcpgAAAQDAEcwRQIgBgvA5mF9+Cag
                                                        O+dgCae812H+XE/bPVGJKBRDMXs/ouACIQCtMLYatqrCGeBY5HhW9Zd4JfXEvKPW
                                                        WcJpVIukrg8Q/QB3AEiw42vapkc0D+VqAvqdMOscUgHLVt0sgdm7v6s52IRzAAAB
                                                        hhTfcmoAAAQDAEgwRgIhAL2HX+d8C6HuFC8p4jdIOW7/TtR/H6vVYsuDr+JnhIG0
                                                        AiEA2TKnPBJXRFb0Fdnf91HxpgZ3x+5VAeXlBLJuY0l3INwwDQYJKoZIhvcNAQEL
                                                        BQADggEBAI/s01poeEqjj5LQ5ifcDEpjbMfjFSKzfajJjt8G3+Otrp7FP4HMvkdU
                                                        gcig0Phzu5IlYXZgaggItmTuFQCq0KRqzwyFhxWgeut6r6C9sGSwuNH0t54izjMp
                                                        wAYXVcN8kExvfAFqD/NszyHVSjJ9sQzC5dk70LJzuAlR8Fny3HbHVnTcgg7OlLFU
                                                        mf7xg2j3VuDbEQvdCBk5hWtCGFoYwzuxvR1Ge7jGyFYvEi4xGwv4pdTrIFByMumt
                                                        FpPjrKqZ2wS2IjT9ZoMzB+2wdgiGqt7aPZfFMQ6hgEA6TuTSeC+kt+WkkaTrYwOt
                                                        nXeBb/qnIWbpLlnqAwNxpcfZKod+JCk=
                                                        -----END CERTIFICATE-----
                                                    EOT
                                                    publicKey               = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsOGI27daFYr1+mSaPO7qj2fW+Fgs+3cQ2/k0MYHUUvsSD36SHjY88M38TGT2OqTZwm9YRAkViZBqtYOeV0OCz8z0qW+/VXKTGlI7K3S2420T3smLurRXwhQI6XRtkENpyTDAN2ca+ZqXgDzWYEG8VCe0VKuUxxKQYFagm0XQ7hoN2CkZq1zcLdMZ+euoaDTRYhO4OUTiOzQ8Uh49RqG5f7HzhkweeyYYtmjlzH3fgIdd7qhDHGOjej8rnu5GFZlPRgWv3g9VhmfCs4GSMbI2dbJyf4QuxeI9PNmPUdvP4oAqFYQwgkx+CYHgW4Dvxg6VG5dHyVY584inJWxNHd3x4wIDAQAB"
                                                    publicKeyAlgorithm      = "RSA"
                                                    publicKeyFormat         = "X.509"
                                                    selfSigned              = false
                                                    serialNumber            = "18717981763630676590532216181853662388"
                                                    sha1Fingerprint         = "243508efb0a29090c539bc170eac4ed2f4db9e62"
                                                    sigAlgName              = "SHA256withRSA"
                                                    subjectAlternativeNames = [
                                                        "hipercard.cloud.itau.com.br",
                                                    ]
                                                    subjectCN               = "hipercard.cloud.itau.com.br"
                                                    subjectRDNs             = {
                                                        CN = "hipercard.cloud.itau.com.br"
                                                    }
                                                    version                 = 3
                                                },
                                            ]
                                            customValidCnValues            = [
                                                "{{Origin Hostname}}",
                                                "{{Forward Host Header}}",
                                            ]
                                            enableTrueClientIp             = false
                                            forwardHostHeader              = "ORIGIN_HOSTNAME"
                                            hostname                       = "hipercard.cloud.itau.com.br"
                                            httpPort                       = 80
                                            httpsPort                      = 443
                                            ipVersion                      = "IPV4"
                                            minTlsVersion                  = "DYNAMIC"
                                            originCertificate              = ""
                                            originCertsToHonor             = "COMBO"
                                            originSni                      = true
                                            originType                     = "CUSTOMER"
                                            ports                          = ""
                                            standardCertificateAuthorities = [
                                                "akamai-permissive",
                                                "THIRD_PARTY_AMAZON",
                                            ]
                                            useUniqueCacheKey              = false
                                            verificationMode               = "CUSTOM"
                                        }
                                    },
                                    {
                                        name    = "cpCode"
                                        options = {
                                            value = {
                                                cpCodeLimits = null
                                                createdDate  = 1626102115000
                                                description  = "BR - Itau - ION - www.hipercard.com.br-cloud"
                                                id           = 1211312
                                                name         = "BR - Itau - ION - www.hipercard.com.br-cloud"
                                                products     = [
                                                    "Fresca",
                                                ]
                                            }
                                        }
                                    },
                                ]
                                criteria            = [
                                    {
                                        name    = "cloudletsOrigin"
                                        options = {
                                            originId = "hipercard.cloud.itau.com.br"
                                        }
                                    },
                                ]
                                criteriaMustSatisfy = "all"
                                name                = "hipercard - hipercard.cloud.itau.com.br"
                                options             = {}
                            },
                        ]
                        criteriaMustSatisfy = "all"
                        name                = "Conditional Origin Group"
                        options             = {}
                    },
                ]
                variables = [
                    {
                        description = ""
                        hidden      = false
                        name        = "PMUSER_REDIR"
                        sensitive   = false
                        value       = ""
                    },
                    {
                        description = ""
                        hidden      = false
                        name        = "PMUSER_REDIR2"
                        sensitive   = false
                        value       = ""
                    },
                ]
            }
        }
    )
    version_notes      = <<-EOT
        Change Edge Hostname
        Case: F-CS-9005048
    EOT

    hostnames {
        cert_provisioning_type = "CPS_MANAGED"
        cname_from             = "hipercard.com.br"
        cname_to               = "ovsan4-www.personnalite.com.br.edgekey.net"
        cname_type             = "EDGE_HOSTNAME"

        cert_status {}
    }
}
