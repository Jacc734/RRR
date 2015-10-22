var EncodingUtilsObject = {
    DecodeHexStringToByteArray: 
        function (hexString) {
            var result = [];
            while (hexString.length >= 2) { 
                result.push(parseInt(hexString.substring(0, 2), 16));
                hexString = hexString.substring(2, hexString.length);
            }
            return result;
        },

    EncodePlainStringToByteArray:
        function(plainString) {
            var result = [];
            for (var i = 0; i < plainString.length; i++) {
                result.push(plainString[i].charCodeAt());
            }
            return result;
        },
    
    EncodeByteArrayToHexString:
        function (plainByteArray) {
            var result = "";
            for (var i = 0; i < plainByteArray.length; i++) {
                result += plainByteArray[i].toString(16);
            }
            return result;
        },

    DecodeByteArrayToPlainString:
        function (plainByteArray) {
            var result = "";
            for (var i = 0; i < plainByteArray.length; i++)
                result += String.fromCharCode(plainByteArray[i]);
            return result;
        }
}
