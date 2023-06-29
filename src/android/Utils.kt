package com.nostr.band.keyStore;

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonPrimitive
import com.google.gson.JsonSerializationContext
import com.google.gson.JsonSerializer
import fr.acinq.secp256k1.Secp256k1
import org.spongycastle.util.encoders.Hex
import java.lang.reflect.Type
import java.security.MessageDigest

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

}

fun ByteArray.toHex() = String(Hex.encode(this))