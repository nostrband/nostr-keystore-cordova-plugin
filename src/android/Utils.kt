package com.nostr.band.keyStore;

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonPrimitive
import com.google.gson.JsonSerializationContext
import com.google.gson.JsonSerializer
import fr.acinq.secp256k1.Secp256k1
import org.spongycastle.util.encoders.Base64
import org.spongycastle.util.encoders.Hex
import java.lang.reflect.Type
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object Utils {

    private val secp256k1 = Secp256k1.get()

    private val sha256: MessageDigest = MessageDigest.getInstance("SHA-256")

    private val gson: Gson = GsonBuilder()
            .disableHtmlEscaping()
            .registerTypeAdapter(ByteArray::class.java, ByteArraySerializer())
            .create()

    class ByteArraySerializer : JsonSerializer<ByteArray> {
        override fun serialize(
                src: ByteArray,
                typeOfSrc: Type?,
                context: JsonSerializationContext?
        ) = JsonPrimitive(src.toHex())
    }

    @JvmStatic
    fun generateId(
            pubKey: ByteArray,
            createdAt: Long,
            kind: Int,
            tags: List<List<String>>,
            content: String
    ): ByteArray {
        val rawEventJson = gson.toJson(listOf(0, pubKey.toHex(), createdAt, kind, tags, content));
        return sha256.digest(rawEventJson.toByteArray())
    }

    @JvmStatic
    fun pubkeyCreate(privKey: ByteArray) = secp256k1.pubKeyCompress(secp256k1.pubkeyCreate(privKey)).copyOfRange(1, 33)

    @JvmStatic
    fun sign(data: ByteArray, privKey: ByteArray): ByteArray = secp256k1.signSchnorr(data, privKey, null)

    @JvmStatic
    fun encrypt(msg: String, privateKey: ByteArray, pubKey: ByteArray): String {
        val sharedSecret = getSharedSecret(privateKey, pubKey)
        return encrypt(msg, sharedSecret)
    }

    @JvmStatic
    fun encrypt(msg: String, sharedSecret: ByteArray): String {
        val iv = ByteArray(16)
        random.nextBytes(iv)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sharedSecret, "AES"), IvParameterSpec(iv))
        val ivBase64 = Base64.toBase64String(iv)
        val encryptedMsg = cipher.doFinal(msg.toByteArray())
        val encryptedMsgBase64 = Base64.toBase64String(encryptedMsg)
        return "$encryptedMsgBase64?iv=$ivBase64"
    }

    @JvmStatic
    fun decrypt(msg: String, privateKey: ByteArray, pubKey: ByteArray): String {
        val sharedSecret = getSharedSecret(privateKey, pubKey)
        return decrypt(msg, sharedSecret)
    }

    @JvmStatic
    fun decrypt(msg: String, sharedSecret: ByteArray): String {
        val parts = msg.split("?iv=")
        val iv = parts[1].run { Base64.decode(this) }
        val encryptedMsg = parts.first().run { Base64.decode(this) }
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(sharedSecret, "AES"), IvParameterSpec(iv))
        return String(cipher.doFinal(encryptedMsg))
    }

    fun getSharedSecret(privateKey: ByteArray, pubKey: ByteArray): ByteArray =
            secp256k1.pubKeyTweakMul(Hex.decode("02") + pubKey, privateKey).copyOfRange(1, 33)

    private val random = SecureRandom()

}

fun ByteArray.toHex() = String(Hex.encode(this))