var FileUtilsObject = {
    ReadTextFile: function (filePath) {
        var fileContents = '';
        try {
            var rawFile = new XMLHttpRequest();
            rawFile.open("GET", filePath, false);
            rawFile.onreadystatechange = function () {
                if (rawFile.readyState === 4 && 
                    (rawFile.status === 200 || rawFile.status === 0))
                    fileContents = rawFile.responseText;
            }
            rawFile.send(null);
        } catch (e) {
            console.log('Error reading the file (%s). Error: %s', filePath, e);
        }
        return fileContents;
    },
    WriteTextFile:  
        function (filePath, content) {
            var textFileAsBlob = new Blob([content], {type:'text/plain'});
            var downloadLink = document.createElement("a");
            downloadLink.download = filePath;
            downloadLink.innerHTML = "Download File";
            if (window.webkitURL != null) {
                // Chrome allows the link to be clicked
                // without actually adding it to the DOM.
                downloadLink.href = window.webkitURL.createObjectURL(textFileAsBlob);
            } else {
                // Firefox requires the link to be added to the DOM
                // before it can be clicked.
                downloadLink.href = window.URL.createObjectURL(textFileAsBlob);
                //downloadLink.onclick = destroyClickedElement;
                downloadLink.style.display = "none";
                document.body.appendChild(downloadLink);
            }

            downloadLink.click();
        }
}
