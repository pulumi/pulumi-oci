// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.LoadBalancer.outputs.RuleSetItemCondition;
import com.pulumi.oci.LoadBalancer.outputs.RuleSetItemRedirectUri;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class RuleSetItem {
    /**
     * @return (Updatable) The action can be one of these values: `ADD_HTTP_REQUEST_HEADER`, `ADD_HTTP_RESPONSE_HEADER`, `ALLOW`, `CONTROL_ACCESS_USING_HTTP_METHODS`, `EXTEND_HTTP_REQUEST_HEADER_VALUE`, `EXTEND_HTTP_RESPONSE_HEADER_VALUE`, `HTTP_HEADER`, `REDIRECT`, `REMOVE_HTTP_REQUEST_HEADER`, `REMOVE_HTTP_RESPONSE_HEADER`
     * 
     */
    private String action;
    /**
     * @return (Updatable) The list of HTTP methods allowed for this listener.
     * 
     */
    private @Nullable List<String> allowedMethods;
    /**
     * @return (Updatable) Indicates whether or not invalid characters in client header fields will be allowed. Valid names are composed of English letters, digits, hyphens and underscores. If &#34;true&#34;, invalid characters are allowed in the HTTP header. If &#34;false&#34;, invalid characters are not allowed in the HTTP header
     * 
     */
    private @Nullable Boolean areInvalidCharactersAllowed;
    /**
     * @return (Updatable)
     * 
     */
    private @Nullable List<RuleSetItemCondition> conditions;
    /**
     * @return (Updatable) A brief description of the access control rule. Avoid entering confidential information.
     * 
     */
    private @Nullable String description;
    /**
     * @return (Updatable) A header name that conforms to RFC 7230.  Example: `example_header_name`
     * 
     */
    private @Nullable String header;
    /**
     * @return (Updatable) The maximum size of each buffer used for reading http client request header. This value indicates the maximum size allowed for each buffer. The allowed values for buffer size are 8, 16, 32 and 64.
     * 
     */
    private @Nullable Integer httpLargeHeaderSizeInKb;
    /**
     * @return (Updatable) A string to prepend to the header value. The resulting header value must still conform to RFC 7230. With the following exceptions:
     * *  value cannot contain `$`
     * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
     * 
     */
    private @Nullable String prefix;
    /**
     * @return (Updatable) An object that defines the redirect URI applied to the original request. The object property values compose the redirect URI.
     * 
     */
    private @Nullable RuleSetItemRedirectUri redirectUri;
    /**
     * @return (Updatable) The HTTP status code to return when the incoming request is redirected.
     * 
     */
    private @Nullable Integer responseCode;
    /**
     * @return (Updatable) The HTTP status code to return when the requested HTTP method is not in the list of allowed methods. The associated status line returned with the code is mapped from the standard HTTP specification. The default value is `405 (Method Not Allowed)`.  Example: 403
     * 
     */
    private @Nullable Integer statusCode;
    /**
     * @return (Updatable) A string to append to the header value. The resulting header value must still conform to RFC 7230. With the following exceptions:
     * *  value cannot contain `$`
     * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
     * 
     */
    private @Nullable String suffix;
    /**
     * @return (Updatable) A header value that conforms to RFC 7230. With the following exceptions:
     * *  value cannot contain `$`
     * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
     * 
     */
    private @Nullable String value;

    private RuleSetItem() {}
    /**
     * @return (Updatable) The action can be one of these values: `ADD_HTTP_REQUEST_HEADER`, `ADD_HTTP_RESPONSE_HEADER`, `ALLOW`, `CONTROL_ACCESS_USING_HTTP_METHODS`, `EXTEND_HTTP_REQUEST_HEADER_VALUE`, `EXTEND_HTTP_RESPONSE_HEADER_VALUE`, `HTTP_HEADER`, `REDIRECT`, `REMOVE_HTTP_REQUEST_HEADER`, `REMOVE_HTTP_RESPONSE_HEADER`
     * 
     */
    public String action() {
        return this.action;
    }
    /**
     * @return (Updatable) The list of HTTP methods allowed for this listener.
     * 
     */
    public List<String> allowedMethods() {
        return this.allowedMethods == null ? List.of() : this.allowedMethods;
    }
    /**
     * @return (Updatable) Indicates whether or not invalid characters in client header fields will be allowed. Valid names are composed of English letters, digits, hyphens and underscores. If &#34;true&#34;, invalid characters are allowed in the HTTP header. If &#34;false&#34;, invalid characters are not allowed in the HTTP header
     * 
     */
    public Optional<Boolean> areInvalidCharactersAllowed() {
        return Optional.ofNullable(this.areInvalidCharactersAllowed);
    }
    /**
     * @return (Updatable)
     * 
     */
    public List<RuleSetItemCondition> conditions() {
        return this.conditions == null ? List.of() : this.conditions;
    }
    /**
     * @return (Updatable) A brief description of the access control rule. Avoid entering confidential information.
     * 
     */
    public Optional<String> description() {
        return Optional.ofNullable(this.description);
    }
    /**
     * @return (Updatable) A header name that conforms to RFC 7230.  Example: `example_header_name`
     * 
     */
    public Optional<String> header() {
        return Optional.ofNullable(this.header);
    }
    /**
     * @return (Updatable) The maximum size of each buffer used for reading http client request header. This value indicates the maximum size allowed for each buffer. The allowed values for buffer size are 8, 16, 32 and 64.
     * 
     */
    public Optional<Integer> httpLargeHeaderSizeInKb() {
        return Optional.ofNullable(this.httpLargeHeaderSizeInKb);
    }
    /**
     * @return (Updatable) A string to prepend to the header value. The resulting header value must still conform to RFC 7230. With the following exceptions:
     * *  value cannot contain `$`
     * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
     * 
     */
    public Optional<String> prefix() {
        return Optional.ofNullable(this.prefix);
    }
    /**
     * @return (Updatable) An object that defines the redirect URI applied to the original request. The object property values compose the redirect URI.
     * 
     */
    public Optional<RuleSetItemRedirectUri> redirectUri() {
        return Optional.ofNullable(this.redirectUri);
    }
    /**
     * @return (Updatable) The HTTP status code to return when the incoming request is redirected.
     * 
     */
    public Optional<Integer> responseCode() {
        return Optional.ofNullable(this.responseCode);
    }
    /**
     * @return (Updatable) The HTTP status code to return when the requested HTTP method is not in the list of allowed methods. The associated status line returned with the code is mapped from the standard HTTP specification. The default value is `405 (Method Not Allowed)`.  Example: 403
     * 
     */
    public Optional<Integer> statusCode() {
        return Optional.ofNullable(this.statusCode);
    }
    /**
     * @return (Updatable) A string to append to the header value. The resulting header value must still conform to RFC 7230. With the following exceptions:
     * *  value cannot contain `$`
     * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
     * 
     */
    public Optional<String> suffix() {
        return Optional.ofNullable(this.suffix);
    }
    /**
     * @return (Updatable) A header value that conforms to RFC 7230. With the following exceptions:
     * *  value cannot contain `$`
     * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
     * 
     */
    public Optional<String> value() {
        return Optional.ofNullable(this.value);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(RuleSetItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String action;
        private @Nullable List<String> allowedMethods;
        private @Nullable Boolean areInvalidCharactersAllowed;
        private @Nullable List<RuleSetItemCondition> conditions;
        private @Nullable String description;
        private @Nullable String header;
        private @Nullable Integer httpLargeHeaderSizeInKb;
        private @Nullable String prefix;
        private @Nullable RuleSetItemRedirectUri redirectUri;
        private @Nullable Integer responseCode;
        private @Nullable Integer statusCode;
        private @Nullable String suffix;
        private @Nullable String value;
        public Builder() {}
        public Builder(RuleSetItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.action = defaults.action;
    	      this.allowedMethods = defaults.allowedMethods;
    	      this.areInvalidCharactersAllowed = defaults.areInvalidCharactersAllowed;
    	      this.conditions = defaults.conditions;
    	      this.description = defaults.description;
    	      this.header = defaults.header;
    	      this.httpLargeHeaderSizeInKb = defaults.httpLargeHeaderSizeInKb;
    	      this.prefix = defaults.prefix;
    	      this.redirectUri = defaults.redirectUri;
    	      this.responseCode = defaults.responseCode;
    	      this.statusCode = defaults.statusCode;
    	      this.suffix = defaults.suffix;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder action(String action) {
            this.action = Objects.requireNonNull(action);
            return this;
        }
        @CustomType.Setter
        public Builder allowedMethods(@Nullable List<String> allowedMethods) {
            this.allowedMethods = allowedMethods;
            return this;
        }
        public Builder allowedMethods(String... allowedMethods) {
            return allowedMethods(List.of(allowedMethods));
        }
        @CustomType.Setter
        public Builder areInvalidCharactersAllowed(@Nullable Boolean areInvalidCharactersAllowed) {
            this.areInvalidCharactersAllowed = areInvalidCharactersAllowed;
            return this;
        }
        @CustomType.Setter
        public Builder conditions(@Nullable List<RuleSetItemCondition> conditions) {
            this.conditions = conditions;
            return this;
        }
        public Builder conditions(RuleSetItemCondition... conditions) {
            return conditions(List.of(conditions));
        }
        @CustomType.Setter
        public Builder description(@Nullable String description) {
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder header(@Nullable String header) {
            this.header = header;
            return this;
        }
        @CustomType.Setter
        public Builder httpLargeHeaderSizeInKb(@Nullable Integer httpLargeHeaderSizeInKb) {
            this.httpLargeHeaderSizeInKb = httpLargeHeaderSizeInKb;
            return this;
        }
        @CustomType.Setter
        public Builder prefix(@Nullable String prefix) {
            this.prefix = prefix;
            return this;
        }
        @CustomType.Setter
        public Builder redirectUri(@Nullable RuleSetItemRedirectUri redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }
        @CustomType.Setter
        public Builder responseCode(@Nullable Integer responseCode) {
            this.responseCode = responseCode;
            return this;
        }
        @CustomType.Setter
        public Builder statusCode(@Nullable Integer statusCode) {
            this.statusCode = statusCode;
            return this;
        }
        @CustomType.Setter
        public Builder suffix(@Nullable String suffix) {
            this.suffix = suffix;
            return this;
        }
        @CustomType.Setter
        public Builder value(@Nullable String value) {
            this.value = value;
            return this;
        }
        public RuleSetItem build() {
            final var o = new RuleSetItem();
            o.action = action;
            o.allowedMethods = allowedMethods;
            o.areInvalidCharactersAllowed = areInvalidCharactersAllowed;
            o.conditions = conditions;
            o.description = description;
            o.header = header;
            o.httpLargeHeaderSizeInKb = httpLargeHeaderSizeInKb;
            o.prefix = prefix;
            o.redirectUri = redirectUri;
            o.responseCode = responseCode;
            o.statusCode = statusCode;
            o.suffix = suffix;
            o.value = value;
            return o;
        }
    }
}