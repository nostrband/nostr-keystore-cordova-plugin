package com.nostr.band.keyStore;

import android.content.Context
import android.util.Log
import java.io.ByteArrayOutputStream

// Helper function for storing keys to internal storage.
object KeyStorage {

    private const val SKS_FILENAME = "SKS_KEY_FILE"
    private const val TAG = "KeyStorageLogTag"

    @JvmStatic
    fun writeValues(context: Context, keyAlias: String, vals: ByteArray?) {
        try {
            val fos = context.openFileOutput(SKS_FILENAME + keyAlias, Context.MODE_PRIVATE)
            fos.write(vals)
            fos.close()
        } catch (e: Exception) {
            Log.e(TAG, "Exception: " + e.message)
        }
    }

    @JvmStatic
    fun readValues(context: Context, keyAlias: String): ByteArray {
        return try {
            val fis = context.openFileInput(SKS_FILENAME + keyAlias)
            val buffer = ByteArray(8192)
            var bytesRead: Int
            val bos = ByteArrayOutputStream()
            while (fis.read(buffer).also { bytesRead = it } != -1) {
                bos.write(buffer, 0, bytesRead)
            }
            val cipherText = bos.toByteArray()
            fis.close()
            cipherText
        } catch (e: Exception) {
            Log.e(TAG, "Exception: " + e.message)
            ByteArray(0)
        }
    }
}