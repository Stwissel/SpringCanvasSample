/**
 * Copyright (c) 2011, salesforce.com, inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *    Redistributions of source code must retain the above copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 *    Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
 *    the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 *    Neither the name of salesforce.com, inc. nor the names of its contributors may be used to endorse or
 *    promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package canvas;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 *
 * The utility method can be used to validate/verify the signed request. In this
 * case, the signed request is verified that it is from Salesforce and that it
 * has not been tampered with.
 * <p>
 * <strike>This utility class has two methods. One verifies and decodes the
 * request as a Java object the other as a JSON String.</strike>
 *
 * Slightly modified: only one method and it returns a JsonNode
 *
 */
public class SignedRequest {

    public static JsonNode verifyAndDecodeAsJson(final String input, final String secret) throws SecurityException {

        final String[] split = SignedRequest.getParts(input);

        final String encodedSig = split[0];
        final String encodedEnvelope = split[1];

        final String json_envelope = new String(Base64.getMimeDecoder().decode(encodedEnvelope));
        final ObjectMapper mapper = new ObjectMapper();
        JsonNode json = null;
        try {
            json = mapper.readTree(json_envelope);
        } catch (final IOException e) {
            throw new SecurityException(String.format("Error [%s] deserializing JSON to JsonNode]", e.getMessage()), e);
        }

        final JsonNode algorithmCandidate = json.get("algorithm");
        if (algorithmCandidate == null) {
            throw new SecurityException("Error: algorithm missing from payload");
        }
        final String algorithm = algorithmCandidate.textValue();

        // Here the check runs - throws an error if it fails
        SignedRequest.verify(secret, algorithm, encodedEnvelope, encodedSig);

        // If we got this far, then the request was not tampered with.
        // return the request as a JsonNode.
        return json;
    }

    private static String[] getParts(final String input) {

        if ((input == null) || (input.indexOf(".") <= 0)) {
            throw new SecurityException(String.format("Input [%s] doesn't look like a signed request", input));
        }

        final String[] split = input.split("[.]", 2);
        return split;
    }

    private static void verify(final String secret, final String algorithm, final String encodedEnvelope,
            final String encodedSig)
            throws SecurityException {
        if ((secret == null) || (secret.trim().length() == 0)) {
            throw new IllegalArgumentException(
                    "secret is null, did you set your environment variable CANVAS_CONSUMER_SECRET?");
        }

        SecretKey hmacKey = null;
        try {
            final byte[] key = secret.getBytes();
            hmacKey = new SecretKeySpec(key, algorithm);
            final Mac mac = Mac.getInstance(algorithm);
            mac.init(hmacKey);

            // Check to see if the body was tampered with
            final byte[] digest = mac.doFinal(encodedEnvelope.getBytes());
            final byte[] decode_sig = Base64.getMimeDecoder().decode(encodedSig);
            if (!Arrays.equals(digest, decode_sig)) {
                final String label = "Warning: Request was tampered with";
                throw new SecurityException(label);
            }
        } catch (final NoSuchAlgorithmException e) {
            throw new SecurityException(
                    String.format("Problem with algorithm [%s] Error [%s]", algorithm, e.getMessage()), e);
        } catch (final InvalidKeyException e) {
            throw new SecurityException(String.format("Problem with key [%s] Error [%s]", hmacKey, e.getMessage()), e);
        }

        // If we got here and didn't throw a SecurityException then all is good.
    }
}
