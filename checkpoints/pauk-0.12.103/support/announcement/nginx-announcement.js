import fs from 'fs';

function value(request) {
    try {
        const value = fs.readFileSync('/var/lib/pauk-subscription-announcement/announce.b64', 'utf8');
        if (value === '') return '';
        if (value.length <= 1075 && /^base64:[A-Za-z0-9+/]+={0,2}$/.test(value)) return value;
    } catch (error) {
        request.error('Cannot read PAUK subscription announcement');
    }
    return request.variables.upstream_http_announce || '';
}

export default {value};
