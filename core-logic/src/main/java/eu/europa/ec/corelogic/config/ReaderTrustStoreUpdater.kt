/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */

package eu.europa.ec.corelogic.config

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class ReaderTrustStoreUpdater(
    private val context: Context,
    private val pemUrl: String
) {

    companion object {
        private const val TAG = "ReaderTrustStoreUpdater"
        private const val CACHE_FILE = "rp-certificates-cache.pem"
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val READ_TIMEOUT_MS = 15_000

        fun deduplicateByFingerprint(certs: List<X509Certificate>): List<X509Certificate> {
            val seen = mutableSetOf<String>()
            return certs.filter { cert ->
                val md = MessageDigest.getInstance("SHA-256")
                val fingerprint = md.digest(cert.encoded).joinToString(":") { "%02X".format(it) }
                seen.add(fingerprint)
            }
        }
    }

    private val cacheFile: File get() = File(context.filesDir, CACHE_FILE)

    suspend fun fetchCertificates(): List<X509Certificate> = withContext(Dispatchers.IO) {
        try {
            val pem = downloadPem()
            if (pem.isNotBlank()) {
                cacheFile.writeText(pem)
                Log.i(TAG, "Fetched and cached certificates from $pemUrl")
                return@withContext parsePem(pem)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to fetch certificates from $pemUrl: ${e.message}")
        }

        if (cacheFile.exists()) {
            val staleMs = System.currentTimeMillis() - cacheFile.lastModified()
            val staleHours = staleMs / (1000 * 3600)
            Log.i(TAG, "Using cached certificates (${staleHours}h old)")
            try {
                return@withContext parsePem(cacheFile.readText())
            } catch (e: Exception) {
                Log.w(TAG, "Failed to parse cached certificates: ${e.message}")
            }
        }

        Log.i(TAG, "No certificates available (no cache)")
        emptyList()
    }

    private fun downloadPem(): String {
        val url = URL(pemUrl)
        val conn = url.openConnection() as HttpURLConnection
        conn.connectTimeout = CONNECT_TIMEOUT_MS
        conn.readTimeout = READ_TIMEOUT_MS
        conn.requestMethod = "GET"

        try {
            val responseCode = conn.responseCode
            if (responseCode != HttpURLConnection.HTTP_OK) {
                Log.w(TAG, "HTTP $responseCode from $pemUrl")
                return ""
            }
            return conn.inputStream.bufferedReader().readText()
        } finally {
            conn.disconnect()
        }
    }

    private fun parsePem(pem: String): List<X509Certificate> {
        if (pem.isBlank()) return emptyList()
        val cf = CertificateFactory.getInstance("X.509")
        val certs = cf.generateCertificates(pem.byteInputStream())
        val result = certs.filterIsInstance<X509Certificate>()
        Log.i(TAG, "Parsed ${result.size} certificates")
        return result
    }
}
