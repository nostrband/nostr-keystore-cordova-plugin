package com.nostr.band.keyStore;

/**
 * Bech32 works with 5 bits values, we use this type to make it explicit: whenever you see Int5 it means 5 bits values,
 * and whenever you see Byte it means 8 bits values.
 */
typealias Int5 = Byte

/**
 * Bech32 and Bech32m address formats.
 * See https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki and https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki.
 */
object Bech32 {
    const val alphabet: String = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    enum class Encoding(val constant: Int) {
        Bech32(1),
        Bech32m(0x2bc830a3),
        Beck32WithoutChecksum(0),
    }

    // char -> 5 bits value
    private val map = Array<Int5>(255) { -1 }

    init {
        for (i in 0..alphabet.lastIndex) {
            map[alphabet[i].code] = i.toByte()
        }
    }

    private fun expand(hrp: String): Array<Int5> {
        val result = Array<Int5>(hrp.length + 1 + hrp.length) { 0 }
        for (i in hrp.indices) {
            result[i] = hrp[i].code.shr(5).toByte()
            result[hrp.length + 1 + i] = (hrp[i].code and 31).toByte()
        }
        result[hrp.length] = 0
        return result
    }

    private fun polymod(values: Array<Int5>, values1: Array<Int5>): Int {
        val GEN = arrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
        var chk = 1
        values.forEach { v ->
            val b = chk shr 25
            chk = ((chk and 0x1ffffff) shl 5) xor v.toInt()
            for (i in 0..5) {
                if (((b shr i) and 1) != 0) chk = chk xor GEN[i]
            }
        }
        values1.forEach { v ->
            val b = chk shr 25
            chk = ((chk and 0x1ffffff) shl 5) xor v.toInt()
            for (i in 0..5) {
                if (((b shr i) and 1) != 0) chk = chk xor GEN[i]
            }
        }
        return chk
    }

    /**
     * decodes a bech32 string
     * @param bech32 bech32 string
     * @param noChecksum if true, the bech32 string doesn't have a checksum
     * @return a (hrp, data, encoding) tuple
     */
    @JvmStatic
    fun decode(bech32: String, noChecksum: Boolean = false): Triple<String, Array<Int5>, Encoding> {
        require(bech32.lowercase() == bech32 || bech32.uppercase() == bech32) { "mixed case strings are not valid bech32" }
        bech32.forEach { require(it.code in 33..126) { "invalid character " } }
        val input = bech32.lowercase()
        val pos = input.lastIndexOf('1')
        val hrp = input.take(pos)
        require(hrp.length in 1..83) { "hrp must contain 1 to 83 characters" }
        val data = Array<Int5>(input.length - pos - 1) { 0 }
        for (i in 0..data.lastIndex) data[i] = map[input[pos + 1 + i].code]
        return if (noChecksum) {
            Triple(hrp, data, Encoding.Beck32WithoutChecksum)
        } else {
            val encoding = when (polymod(expand(hrp), data)) {
                Encoding.Bech32.constant -> Encoding.Bech32
                Encoding.Bech32m.constant -> Encoding.Bech32m
                else -> throw IllegalArgumentException("invalid checksum for $bech32")
            }
            Triple(hrp, data.dropLast(6).toTypedArray(), encoding)
        }
    }

    /**
     * decodes a bech32 string
     * @param bech32 bech32 string
     * @param noChecksum if true, the bech32 string doesn't have a checksum
     * @return a (hrp, data, encoding) tuple
     */
    @JvmStatic
    fun decodeBytes(
            bech32: String,
            noChecksum: Boolean = false
    ): Triple<String, ByteArray, Encoding> {
        val (hrp, int5s, encoding) = decode(bech32, noChecksum)
        return Triple(hrp, five2eight(int5s, 0), encoding)
    }

    /**
     * @param input a sequence of 5 bits integers
     * @return a sequence of 8 bits integers
     */
    @JvmStatic
    fun five2eight(input: Array<Int5>, offset: Int): ByteArray {
        var buffer = 0L
        val output = ArrayList<Byte>()
        var count = 0
        for (i in offset..input.lastIndex) {
            val b = input[i]
            buffer = (buffer shl 5) or (b.toLong() and 31)
            count += 5
            while (count >= 8) {
                output.add(((buffer shr (count - 8)) and 0xff).toByte())
                count -= 8
            }
        }
        require(count <= 4) { "Zero-padding of more than 4 bits" }
        require((buffer and ((1L shl count) - 1L)) == 0L) { "Non-zero padding in 8-to-5 conversion" }
        return output.toByteArray()
    }

}