# gdrive-proxy

A proxy server for google drive to facillitate downloading large files. It has the following features:

* Parse webpages to get new download URLs for large files if necessary
because these URLs expires quickly (within 10min).
* Manages cookies and stores them to avoid "Quota Exceeded" error.
* Provide the 'Content-Length' header to the client and never use chunked 'Transfer-Encoding'.
This informs the download manager of the total file length and is necessary for `aria2c` to support segmented download. See aria2/aria2#1576.
* Transparent to download managers.
* Standalone single-file python script with no external dependencies.

## Requirements

* Python 3.5 or later. It is tested on 3.8 but it should work with 3.5+. If you have an issue, please let me know.

## Usage
Execute `python3 gdrive-proxy.py -h` to get the basic usage. You may want to set `--port` option for listening port  and `--cookies` to specify where to store cookies permanently across runs.

` $ python3 gdrive-proxy.py --port 8080 --cookies ~/gdrive-cookies.txt `

The proxy is now running on `http://localhost:8080/`

Then to download any file, you'll need to make a "shareable link" to the file and then get its public "ID" from there (example: `https://drive.google.com/open?id=XxXxXxXXXXXXXXxXXXX`)

Now you can use your preferred download manger and pass it the url:

`http://[proxy_address]/[file_id][/optionally_any_trailing_string]`

For example, `http://localhost:8080/AbCdEfGhIjKl`. The optional trailing string can be used to specify file name for download managers that do not honor 'Content-Disposition' header.

## Import browser cookies
You may want to do this when the "shareable link" opens in your browser when you are logged-in,
but it doesn't download when used as above and have error messages link 'Quota exceeded' or 'too many downloads'.

To do this, you need to export your browser's cookies (at least for google domains) in the Netscape format, 
also known as "cookies.txt", and pass it to `--cookies` option. For firefox, for example, see https://superuser.com/questions/666167/how-do-i-use-firefox-cookies-with-wget.

## License
This is available under MIT license. See LICENSE file.
