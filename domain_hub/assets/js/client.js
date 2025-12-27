(function (window) {
    const CFClient = {
        langMap: {},
        config: {},

        setLangMap(map) {
            this.langMap = Object(map) === map ? map : {};
        },

        setConfig(config) {
            this.config = Object(config) === config ? config : {};
        },

        t(key, fallback = '') {
            if (key && Object.prototype.hasOwnProperty.call(this.langMap, key)) {
                return this.langMap[key];
            }
            return fallback;
        },

        format(key, fallback, ...values) {
            let text = this.t(key, fallback);
            if (!values.length) {
                return text;
            }
            values.forEach(function (value) {
                text = text.replace('%s', value);
            });
            return text;
        },

        copyText(text) {
            const value = text || '';
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(value).catch(function () {
                    CFClient.copyTextFallback(value);
                });
                return;
            }
            this.copyTextFallback(value);
        },

        copyTextFallback(text) {
            try {
                const textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.style.position = 'fixed';
                textarea.style.top = '-1000px';
                textarea.style.left = '-1000px';
                document.body.appendChild(textarea);
                textarea.focus();
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);
            } catch (err) {}
        },

        bootstrap() {
            const langProxy = this.t.bind(this);
            const formatProxy = this.format.bind(this);
            window.cfLang = function (key, fallback) {
                return langProxy(key, fallback);
            };
            window.cfLangFormat = function (key, fallback, ...values) {
                return formatProxy(key, fallback, ...values);
            };
            window.copyText = this.copyText.bind(this);
        }
    };

    window.CFClient = CFClient;
})(window);
