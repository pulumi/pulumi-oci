// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class PolicyWafConfigProtectionSettings {
    /**
     * @return (Updatable) The list of allowed HTTP methods. If unspecified, default to `[OPTIONS, GET, HEAD, POST]`. This setting only applies if a corresponding protection rule is enabled, such as the &#34;Restrict HTTP Request Methods&#34; rule (key: 911100).
     * 
     */
    private @Nullable List<String> allowedHttpMethods;
    /**
     * @return (Updatable) If `action` is set to `BLOCK`, this specifies how the traffic is blocked when detected as malicious by a protection rule. If unspecified, defaults to `SET_RESPONSE_CODE`.
     * 
     */
    private @Nullable String blockAction;
    /**
     * @return (Updatable) The error code to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`.
     * 
     */
    private @Nullable String blockErrorPageCode;
    /**
     * @return (Updatable) The description text to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `Access blocked by website owner. Please contact support.`
     * 
     */
    private @Nullable String blockErrorPageDescription;
    /**
     * @return (Updatable) The message to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to &#39;Access to the website is blocked.&#39;
     * 
     */
    private @Nullable String blockErrorPageMessage;
    /**
     * @return (Updatable) The response code returned when `action` is set to `BLOCK`, `blockAction` is set to `SET_RESPONSE_CODE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`. The list of available response codes: `400`, `401`, `403`, `405`, `409`, `411`, `412`, `413`, `414`, `415`, `416`, `500`, `501`, `502`, `503`, `504`, `507`.
     * 
     */
    private @Nullable Integer blockResponseCode;
    /**
     * @return (Updatable) Inspects the response body of origin responses. Can be used to detect leakage of sensitive data. If unspecified, defaults to `false`.
     * 
     * **Note:** Only origin responses with a Content-Type matching a value in `mediaTypes` will be inspected.
     * 
     */
    private @Nullable Boolean isResponseInspected;
    /**
     * @return (Updatable) The maximum number of arguments allowed to be passed to your application before an action is taken. Arguements are query parameters or body parameters in a PUT or POST request. If unspecified, defaults to `255`. This setting only applies if a corresponding protection rule is enabled, such as the &#34;Number of Arguments Limits&#34; rule (key: 960335).  Example: If `maxArgumentCount` to `2` for the Max Number of Arguments protection rule (key: 960335), the following requests would be blocked: `GET /myapp/path?query=one&amp;query=two&amp;query=three` `POST /myapp/path` with Body `{&#34;argument1&#34;:&#34;one&#34;,&#34;argument2&#34;:&#34;two&#34;,&#34;argument3&#34;:&#34;three&#34;}`
     * 
     */
    private @Nullable Integer maxArgumentCount;
    /**
     * @return (Updatable) The maximum length allowed for each argument name, in characters. Arguements are query parameters or body parameters in a PUT or POST request. If unspecified, defaults to `400`. This setting only applies if a corresponding protection rule is enabled, such as the &#34;Values Limits&#34; rule (key: 960208).
     * 
     */
    private @Nullable Integer maxNameLengthPerArgument;
    /**
     * @return (Updatable) The maximum response size to be fully inspected, in binary kilobytes (KiB). Anything over this limit will be partially inspected. If unspecified, defaults to `1024`.
     * 
     */
    private @Nullable Integer maxResponseSizeInKiB;
    /**
     * @return (Updatable) The maximum length allowed for the sum of the argument name and value, in characters. Arguements are query parameters or body parameters in a PUT or POST request. If unspecified, defaults to `64000`. This setting only applies if a corresponding protection rule is enabled, such as the &#34;Total Arguments Limits&#34; rule (key: 960341).
     * 
     */
    private @Nullable Integer maxTotalNameLengthOfArguments;
    /**
     * @return (Updatable) The list of media types to allow for inspection, if `isResponseInspected` is enabled. Only responses with MIME types in this list will be inspected. If unspecified, defaults to `[&#34;text/html&#34;, &#34;text/plain&#34;, &#34;text/xml&#34;]`.
     * 
     * Supported MIME types include:
     * * text/html
     * * text/plain
     * * text/asp
     * * text/css
     * * text/x-script
     * * application/json
     * * text/webviewhtml
     * * text/x-java-source
     * * application/x-javascript
     * * application/javascript
     * * application/ecmascript
     * * text/javascript
     * * text/ecmascript
     * * text/x-script.perl
     * * text/x-script.phyton
     * * application/plain
     * * application/xml
     * * text/xml
     * 
     */
    private @Nullable List<String> mediaTypes;
    /**
     * @return (Updatable) The length of time to analyze traffic traffic, in days. After the analysis period, `WafRecommendations` will be populated. If unspecified, defaults to `10`.
     * 
     * Use `GET /waasPolicies/{waasPolicyId}/wafRecommendations` to view WAF recommendations.
     * 
     */
    private @Nullable Integer recommendationsPeriodInDays;

    private PolicyWafConfigProtectionSettings() {}
    /**
     * @return (Updatable) The list of allowed HTTP methods. If unspecified, default to `[OPTIONS, GET, HEAD, POST]`. This setting only applies if a corresponding protection rule is enabled, such as the &#34;Restrict HTTP Request Methods&#34; rule (key: 911100).
     * 
     */
    public List<String> allowedHttpMethods() {
        return this.allowedHttpMethods == null ? List.of() : this.allowedHttpMethods;
    }
    /**
     * @return (Updatable) If `action` is set to `BLOCK`, this specifies how the traffic is blocked when detected as malicious by a protection rule. If unspecified, defaults to `SET_RESPONSE_CODE`.
     * 
     */
    public Optional<String> blockAction() {
        return Optional.ofNullable(this.blockAction);
    }
    /**
     * @return (Updatable) The error code to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`.
     * 
     */
    public Optional<String> blockErrorPageCode() {
        return Optional.ofNullable(this.blockErrorPageCode);
    }
    /**
     * @return (Updatable) The description text to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `Access blocked by website owner. Please contact support.`
     * 
     */
    public Optional<String> blockErrorPageDescription() {
        return Optional.ofNullable(this.blockErrorPageDescription);
    }
    /**
     * @return (Updatable) The message to show on the error page when `action` is set to `BLOCK`, `blockAction` is set to `SHOW_ERROR_PAGE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to &#39;Access to the website is blocked.&#39;
     * 
     */
    public Optional<String> blockErrorPageMessage() {
        return Optional.ofNullable(this.blockErrorPageMessage);
    }
    /**
     * @return (Updatable) The response code returned when `action` is set to `BLOCK`, `blockAction` is set to `SET_RESPONSE_CODE`, and the traffic is detected as malicious by a protection rule. If unspecified, defaults to `403`. The list of available response codes: `400`, `401`, `403`, `405`, `409`, `411`, `412`, `413`, `414`, `415`, `416`, `500`, `501`, `502`, `503`, `504`, `507`.
     * 
     */
    public Optional<Integer> blockResponseCode() {
        return Optional.ofNullable(this.blockResponseCode);
    }
    /**
     * @return (Updatable) Inspects the response body of origin responses. Can be used to detect leakage of sensitive data. If unspecified, defaults to `false`.
     * 
     * **Note:** Only origin responses with a Content-Type matching a value in `mediaTypes` will be inspected.
     * 
     */
    public Optional<Boolean> isResponseInspected() {
        return Optional.ofNullable(this.isResponseInspected);
    }
    /**
     * @return (Updatable) The maximum number of arguments allowed to be passed to your application before an action is taken. Arguements are query parameters or body parameters in a PUT or POST request. If unspecified, defaults to `255`. This setting only applies if a corresponding protection rule is enabled, such as the &#34;Number of Arguments Limits&#34; rule (key: 960335).  Example: If `maxArgumentCount` to `2` for the Max Number of Arguments protection rule (key: 960335), the following requests would be blocked: `GET /myapp/path?query=one&amp;query=two&amp;query=three` `POST /myapp/path` with Body `{&#34;argument1&#34;:&#34;one&#34;,&#34;argument2&#34;:&#34;two&#34;,&#34;argument3&#34;:&#34;three&#34;}`
     * 
     */
    public Optional<Integer> maxArgumentCount() {
        return Optional.ofNullable(this.maxArgumentCount);
    }
    /**
     * @return (Updatable) The maximum length allowed for each argument name, in characters. Arguements are query parameters or body parameters in a PUT or POST request. If unspecified, defaults to `400`. This setting only applies if a corresponding protection rule is enabled, such as the &#34;Values Limits&#34; rule (key: 960208).
     * 
     */
    public Optional<Integer> maxNameLengthPerArgument() {
        return Optional.ofNullable(this.maxNameLengthPerArgument);
    }
    /**
     * @return (Updatable) The maximum response size to be fully inspected, in binary kilobytes (KiB). Anything over this limit will be partially inspected. If unspecified, defaults to `1024`.
     * 
     */
    public Optional<Integer> maxResponseSizeInKiB() {
        return Optional.ofNullable(this.maxResponseSizeInKiB);
    }
    /**
     * @return (Updatable) The maximum length allowed for the sum of the argument name and value, in characters. Arguements are query parameters or body parameters in a PUT or POST request. If unspecified, defaults to `64000`. This setting only applies if a corresponding protection rule is enabled, such as the &#34;Total Arguments Limits&#34; rule (key: 960341).
     * 
     */
    public Optional<Integer> maxTotalNameLengthOfArguments() {
        return Optional.ofNullable(this.maxTotalNameLengthOfArguments);
    }
    /**
     * @return (Updatable) The list of media types to allow for inspection, if `isResponseInspected` is enabled. Only responses with MIME types in this list will be inspected. If unspecified, defaults to `[&#34;text/html&#34;, &#34;text/plain&#34;, &#34;text/xml&#34;]`.
     * 
     * Supported MIME types include:
     * * text/html
     * * text/plain
     * * text/asp
     * * text/css
     * * text/x-script
     * * application/json
     * * text/webviewhtml
     * * text/x-java-source
     * * application/x-javascript
     * * application/javascript
     * * application/ecmascript
     * * text/javascript
     * * text/ecmascript
     * * text/x-script.perl
     * * text/x-script.phyton
     * * application/plain
     * * application/xml
     * * text/xml
     * 
     */
    public List<String> mediaTypes() {
        return this.mediaTypes == null ? List.of() : this.mediaTypes;
    }
    /**
     * @return (Updatable) The length of time to analyze traffic traffic, in days. After the analysis period, `WafRecommendations` will be populated. If unspecified, defaults to `10`.
     * 
     * Use `GET /waasPolicies/{waasPolicyId}/wafRecommendations` to view WAF recommendations.
     * 
     */
    public Optional<Integer> recommendationsPeriodInDays() {
        return Optional.ofNullable(this.recommendationsPeriodInDays);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(PolicyWafConfigProtectionSettings defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> allowedHttpMethods;
        private @Nullable String blockAction;
        private @Nullable String blockErrorPageCode;
        private @Nullable String blockErrorPageDescription;
        private @Nullable String blockErrorPageMessage;
        private @Nullable Integer blockResponseCode;
        private @Nullable Boolean isResponseInspected;
        private @Nullable Integer maxArgumentCount;
        private @Nullable Integer maxNameLengthPerArgument;
        private @Nullable Integer maxResponseSizeInKiB;
        private @Nullable Integer maxTotalNameLengthOfArguments;
        private @Nullable List<String> mediaTypes;
        private @Nullable Integer recommendationsPeriodInDays;
        public Builder() {}
        public Builder(PolicyWafConfigProtectionSettings defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allowedHttpMethods = defaults.allowedHttpMethods;
    	      this.blockAction = defaults.blockAction;
    	      this.blockErrorPageCode = defaults.blockErrorPageCode;
    	      this.blockErrorPageDescription = defaults.blockErrorPageDescription;
    	      this.blockErrorPageMessage = defaults.blockErrorPageMessage;
    	      this.blockResponseCode = defaults.blockResponseCode;
    	      this.isResponseInspected = defaults.isResponseInspected;
    	      this.maxArgumentCount = defaults.maxArgumentCount;
    	      this.maxNameLengthPerArgument = defaults.maxNameLengthPerArgument;
    	      this.maxResponseSizeInKiB = defaults.maxResponseSizeInKiB;
    	      this.maxTotalNameLengthOfArguments = defaults.maxTotalNameLengthOfArguments;
    	      this.mediaTypes = defaults.mediaTypes;
    	      this.recommendationsPeriodInDays = defaults.recommendationsPeriodInDays;
        }

        @CustomType.Setter
        public Builder allowedHttpMethods(@Nullable List<String> allowedHttpMethods) {

            this.allowedHttpMethods = allowedHttpMethods;
            return this;
        }
        public Builder allowedHttpMethods(String... allowedHttpMethods) {
            return allowedHttpMethods(List.of(allowedHttpMethods));
        }
        @CustomType.Setter
        public Builder blockAction(@Nullable String blockAction) {

            this.blockAction = blockAction;
            return this;
        }
        @CustomType.Setter
        public Builder blockErrorPageCode(@Nullable String blockErrorPageCode) {

            this.blockErrorPageCode = blockErrorPageCode;
            return this;
        }
        @CustomType.Setter
        public Builder blockErrorPageDescription(@Nullable String blockErrorPageDescription) {

            this.blockErrorPageDescription = blockErrorPageDescription;
            return this;
        }
        @CustomType.Setter
        public Builder blockErrorPageMessage(@Nullable String blockErrorPageMessage) {

            this.blockErrorPageMessage = blockErrorPageMessage;
            return this;
        }
        @CustomType.Setter
        public Builder blockResponseCode(@Nullable Integer blockResponseCode) {

            this.blockResponseCode = blockResponseCode;
            return this;
        }
        @CustomType.Setter
        public Builder isResponseInspected(@Nullable Boolean isResponseInspected) {

            this.isResponseInspected = isResponseInspected;
            return this;
        }
        @CustomType.Setter
        public Builder maxArgumentCount(@Nullable Integer maxArgumentCount) {

            this.maxArgumentCount = maxArgumentCount;
            return this;
        }
        @CustomType.Setter
        public Builder maxNameLengthPerArgument(@Nullable Integer maxNameLengthPerArgument) {

            this.maxNameLengthPerArgument = maxNameLengthPerArgument;
            return this;
        }
        @CustomType.Setter
        public Builder maxResponseSizeInKiB(@Nullable Integer maxResponseSizeInKiB) {

            this.maxResponseSizeInKiB = maxResponseSizeInKiB;
            return this;
        }
        @CustomType.Setter
        public Builder maxTotalNameLengthOfArguments(@Nullable Integer maxTotalNameLengthOfArguments) {

            this.maxTotalNameLengthOfArguments = maxTotalNameLengthOfArguments;
            return this;
        }
        @CustomType.Setter
        public Builder mediaTypes(@Nullable List<String> mediaTypes) {

            this.mediaTypes = mediaTypes;
            return this;
        }
        public Builder mediaTypes(String... mediaTypes) {
            return mediaTypes(List.of(mediaTypes));
        }
        @CustomType.Setter
        public Builder recommendationsPeriodInDays(@Nullable Integer recommendationsPeriodInDays) {

            this.recommendationsPeriodInDays = recommendationsPeriodInDays;
            return this;
        }
        public PolicyWafConfigProtectionSettings build() {
            final var _resultValue = new PolicyWafConfigProtectionSettings();
            _resultValue.allowedHttpMethods = allowedHttpMethods;
            _resultValue.blockAction = blockAction;
            _resultValue.blockErrorPageCode = blockErrorPageCode;
            _resultValue.blockErrorPageDescription = blockErrorPageDescription;
            _resultValue.blockErrorPageMessage = blockErrorPageMessage;
            _resultValue.blockResponseCode = blockResponseCode;
            _resultValue.isResponseInspected = isResponseInspected;
            _resultValue.maxArgumentCount = maxArgumentCount;
            _resultValue.maxNameLengthPerArgument = maxNameLengthPerArgument;
            _resultValue.maxResponseSizeInKiB = maxResponseSizeInKiB;
            _resultValue.maxTotalNameLengthOfArguments = maxTotalNameLengthOfArguments;
            _resultValue.mediaTypes = mediaTypes;
            _resultValue.recommendationsPeriodInDays = recommendationsPeriodInDays;
            return _resultValue;
        }
    }
}
