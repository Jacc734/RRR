var FileUtilsObject = {
    ReadTextFile: function (file) {
        var fileContents = '';
        try {
            var rawFile = new XMLHttpRequest();
            rawFile.open("GET", file, false);
            rawFile.onreadystatechange = function () {
                if (rawFile.readyState === 4 && 
                    (rawFile.status === 200 || rawFile.status === 0))
                    fileContents = rawFile.responseText;
            }
            rawFile.send(null);
        } catch (e) {
            console.log('Error reading the file (%s). Error: %s', file, e);
        }
        return fileContents;
    }
}
