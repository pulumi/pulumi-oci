// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LoadBalancer.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.LoadBalancer.inputs.RuleSetItemConditionArgs;
import com.pulumi.oci.LoadBalancer.inputs.RuleSetItemRedirectUriArgs;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class RuleSetItemArgs extends com.pulumi.resources.ResourceArgs {

    public static final RuleSetItemArgs Empty = new RuleSetItemArgs();

    /**
     * (Updatable) The action can be one of these values: `ADD_HTTP_REQUEST_HEADER`, `ADD_HTTP_RESPONSE_HEADER`, `ALLOW`, `CONTROL_ACCESS_USING_HTTP_METHODS`, `EXTEND_HTTP_REQUEST_HEADER_VALUE`, `EXTEND_HTTP_RESPONSE_HEADER_VALUE`, `HTTP_HEADER`, `REDIRECT`, `REMOVE_HTTP_REQUEST_HEADER`, `REMOVE_HTTP_RESPONSE_HEADER`
     * 
     */
    @Import(name="action", required=true)
    private Output<String> action;

    /**
     * @return (Updatable) The action can be one of these values: `ADD_HTTP_REQUEST_HEADER`, `ADD_HTTP_RESPONSE_HEADER`, `ALLOW`, `CONTROL_ACCESS_USING_HTTP_METHODS`, `EXTEND_HTTP_REQUEST_HEADER_VALUE`, `EXTEND_HTTP_RESPONSE_HEADER_VALUE`, `HTTP_HEADER`, `REDIRECT`, `REMOVE_HTTP_REQUEST_HEADER`, `REMOVE_HTTP_RESPONSE_HEADER`
     * 
     */
    public Output<String> action() {
        return this.action;
    }

    /**
     * (Updatable) The list of HTTP methods allowed for this listener.
     * 
     */
    @Import(name="allowedMethods")
    private @Nullable Output<List<String>> allowedMethods;

    /**
     * @return (Updatable) The list of HTTP methods allowed for this listener.
     * 
     */
    public Optional<Output<List<String>>> allowedMethods() {
        return Optional.ofNullable(this.allowedMethods);
    }

    /**
     * (Updatable) Indicates whether or not invalid characters in client header fields will be allowed. Valid names are composed of English letters, digits, hyphens and underscores. If &#34;true&#34;, invalid characters are allowed in the HTTP header. If &#34;false&#34;, invalid characters are not allowed in the HTTP header
     * 
     */
    @Import(name="areInvalidCharactersAllowed")
    private @Nullable Output<Boolean> areInvalidCharactersAllowed;

    /**
     * @return (Updatable) Indicates whether or not invalid characters in client header fields will be allowed. Valid names are composed of English letters, digits, hyphens and underscores. If &#34;true&#34;, invalid characters are allowed in the HTTP header. If &#34;false&#34;, invalid characters are not allowed in the HTTP header
     * 
     */
    public Optional<Output<Boolean>> areInvalidCharactersAllowed() {
        return Optional.ofNullable(this.areInvalidCharactersAllowed);
    }

    /**
     * (Updatable)
     * 
     */
    @Import(name="conditions")
    private @Nullable Output<List<RuleSetItemConditionArgs>> conditions;

    /**
     * @return (Updatable)
     * 
     */
    public Optional<Output<List<RuleSetItemConditionArgs>>> conditions() {
        return Optional.ofNullable(this.conditions);
    }

    /**
     * (Updatable) A brief description of the access control rule. Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) A brief description of the access control rule. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) A header name that conforms to RFC 7230.  Example: `example_header_name`
     * 
     */
    @Import(name="header")
    private @Nullable Output<String> header;

    /**
     * @return (Updatable) A header name that conforms to RFC 7230.  Example: `example_header_name`
     * 
     */
    public Optional<Output<String>> header() {
        return Optional.ofNullable(this.header);
    }

    /**
     * (Updatable) The maximum size of each buffer used for reading http client request header. This value indicates the maximum size allowed for each buffer. The allowed values for buffer size are 8, 16, 32 and 64.
     * 
     */
    @Import(name="httpLargeHeaderSizeInKb")
    private @Nullable Output<Integer> httpLargeHeaderSizeInKb;

    /**
     * @return (Updatable) The maximum size of each buffer used for reading http client request header. This value indicates the maximum size allowed for each buffer. The allowed values for buffer size are 8, 16, 32 and 64.
     * 
     */
    public Optional<Output<Integer>> httpLargeHeaderSizeInKb() {
        return Optional.ofNullable(this.httpLargeHeaderSizeInKb);
    }

    /**
     * (Updatable) A string to prepend to the header value. The resulting header value must still conform to RFC 7230. With the following exceptions:
     * *  value cannot contain `$`
     * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
     * 
     */
    @Import(name="prefix")
    private @Nullable Output<String> prefix;

    /**
     * @return (Updatable) A string to prepend to the header value. The resulting header value must still conform to RFC 7230. With the following exceptions:
     * *  value cannot contain `$`
     * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
     * 
     */
    public Optional<Output<String>> prefix() {
        return Optional.ofNullable(this.prefix);
    }

    /**
     * (Updatable) An object that defines the redirect URI applied to the original request. The object property values compose the redirect URI.
     * 
     */
    @Import(name="redirectUri")
    private @Nullable Output<RuleSetItemRedirectUriArgs> redirectUri;

    /**
     * @return (Updatable) An object that defines the redirect URI applied to the original request. The object property values compose the redirect URI.
     * 
     */
    public Optional<Output<RuleSetItemRedirectUriArgs>> redirectUri() {
        return Optional.ofNullable(this.redirectUri);
    }

    /**
     * (Updatable) The HTTP status code to return when the incoming request is redirected.
     * 
     */
    @Import(name="responseCode")
    private @Nullable Output<Integer> responseCode;

    /**
     * @return (Updatable) The HTTP status code to return when the incoming request is redirected.
     * 
     */
    public Optional<Output<Integer>> responseCode() {
        return Optional.ofNullable(this.responseCode);
    }

    /**
     * (Updatable) The HTTP status code to return when the requested HTTP method is not in the list of allowed methods. The associated status line returned with the code is mapped from the standard HTTP specification. The default value is `405 (Method Not Allowed)`.  Example: 403
     * 
     */
    @Import(name="statusCode")
    private @Nullable Output<Integer> statusCode;

    /**
     * @return (Updatable) The HTTP status code to return when the requested HTTP method is not in the list of allowed methods. The associated status line returned with the code is mapped from the standard HTTP specification. The default value is `405 (Method Not Allowed)`.  Example: 403
     * 
     */
    public Optional<Output<Integer>> statusCode() {
        return Optional.ofNullable(this.statusCode);
    }

    /**
     * (Updatable) A string to append to the header value. The resulting header value must still conform to RFC 7230. With the following exceptions:
     * *  value cannot contain `$`
     * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
     * 
     */
    @Import(name="suffix")
    private @Nullable Output<String> suffix;

    /**
     * @return (Updatable) A string to append to the header value. The resulting header value must still conform to RFC 7230. With the following exceptions:
     * *  value cannot contain `$`
     * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
     * 
     */
    public Optional<Output<String>> suffix() {
        return Optional.ofNullable(this.suffix);
    }

    /**
     * (Updatable) A header value that conforms to RFC 7230. With the following exceptions:
     * *  value cannot contain `$`
     * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
     * 
     */
    @Import(name="value")
    private @Nullable Output<String> value;

    /**
     * @return (Updatable) A header value that conforms to RFC 7230. With the following exceptions:
     * *  value cannot contain `$`
     * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
     * 
     */
    public Optional<Output<String>> value() {
        return Optional.ofNullable(this.value);
    }

    private RuleSetItemArgs() {}

    private RuleSetItemArgs(RuleSetItemArgs $) {
        this.action = $.action;
        this.allowedMethods = $.allowedMethods;
        this.areInvalidCharactersAllowed = $.areInvalidCharactersAllowed;
        this.conditions = $.conditions;
        this.description = $.description;
        this.header = $.header;
        this.httpLargeHeaderSizeInKb = $.httpLargeHeaderSizeInKb;
        this.prefix = $.prefix;
        this.redirectUri = $.redirectUri;
        this.responseCode = $.responseCode;
        this.statusCode = $.statusCode;
        this.suffix = $.suffix;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RuleSetItemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RuleSetItemArgs $;

        public Builder() {
            $ = new RuleSetItemArgs();
        }

        public Builder(RuleSetItemArgs defaults) {
            $ = new RuleSetItemArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param action (Updatable) The action can be one of these values: `ADD_HTTP_REQUEST_HEADER`, `ADD_HTTP_RESPONSE_HEADER`, `ALLOW`, `CONTROL_ACCESS_USING_HTTP_METHODS`, `EXTEND_HTTP_REQUEST_HEADER_VALUE`, `EXTEND_HTTP_RESPONSE_HEADER_VALUE`, `HTTP_HEADER`, `REDIRECT`, `REMOVE_HTTP_REQUEST_HEADER`, `REMOVE_HTTP_RESPONSE_HEADER`
         * 
         * @return builder
         * 
         */
        public Builder action(Output<String> action) {
            $.action = action;
            return this;
        }

        /**
         * @param action (Updatable) The action can be one of these values: `ADD_HTTP_REQUEST_HEADER`, `ADD_HTTP_RESPONSE_HEADER`, `ALLOW`, `CONTROL_ACCESS_USING_HTTP_METHODS`, `EXTEND_HTTP_REQUEST_HEADER_VALUE`, `EXTEND_HTTP_RESPONSE_HEADER_VALUE`, `HTTP_HEADER`, `REDIRECT`, `REMOVE_HTTP_REQUEST_HEADER`, `REMOVE_HTTP_RESPONSE_HEADER`
         * 
         * @return builder
         * 
         */
        public Builder action(String action) {
            return action(Output.of(action));
        }

        /**
         * @param allowedMethods (Updatable) The list of HTTP methods allowed for this listener.
         * 
         * @return builder
         * 
         */
        public Builder allowedMethods(@Nullable Output<List<String>> allowedMethods) {
            $.allowedMethods = allowedMethods;
            return this;
        }

        /**
         * @param allowedMethods (Updatable) The list of HTTP methods allowed for this listener.
         * 
         * @return builder
         * 
         */
        public Builder allowedMethods(List<String> allowedMethods) {
            return allowedMethods(Output.of(allowedMethods));
        }

        /**
         * @param allowedMethods (Updatable) The list of HTTP methods allowed for this listener.
         * 
         * @return builder
         * 
         */
        public Builder allowedMethods(String... allowedMethods) {
            return allowedMethods(List.of(allowedMethods));
        }

        /**
         * @param areInvalidCharactersAllowed (Updatable) Indicates whether or not invalid characters in client header fields will be allowed. Valid names are composed of English letters, digits, hyphens and underscores. If &#34;true&#34;, invalid characters are allowed in the HTTP header. If &#34;false&#34;, invalid characters are not allowed in the HTTP header
         * 
         * @return builder
         * 
         */
        public Builder areInvalidCharactersAllowed(@Nullable Output<Boolean> areInvalidCharactersAllowed) {
            $.areInvalidCharactersAllowed = areInvalidCharactersAllowed;
            return this;
        }

        /**
         * @param areInvalidCharactersAllowed (Updatable) Indicates whether or not invalid characters in client header fields will be allowed. Valid names are composed of English letters, digits, hyphens and underscores. If &#34;true&#34;, invalid characters are allowed in the HTTP header. If &#34;false&#34;, invalid characters are not allowed in the HTTP header
         * 
         * @return builder
         * 
         */
        public Builder areInvalidCharactersAllowed(Boolean areInvalidCharactersAllowed) {
            return areInvalidCharactersAllowed(Output.of(areInvalidCharactersAllowed));
        }

        /**
         * @param conditions (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder conditions(@Nullable Output<List<RuleSetItemConditionArgs>> conditions) {
            $.conditions = conditions;
            return this;
        }

        /**
         * @param conditions (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder conditions(List<RuleSetItemConditionArgs> conditions) {
            return conditions(Output.of(conditions));
        }

        /**
         * @param conditions (Updatable)
         * 
         * @return builder
         * 
         */
        public Builder conditions(RuleSetItemConditionArgs... conditions) {
            return conditions(List.of(conditions));
        }

        /**
         * @param description (Updatable) A brief description of the access control rule. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) A brief description of the access control rule. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param header (Updatable) A header name that conforms to RFC 7230.  Example: `example_header_name`
         * 
         * @return builder
         * 
         */
        public Builder header(@Nullable Output<String> header) {
            $.header = header;
            return this;
        }

        /**
         * @param header (Updatable) A header name that conforms to RFC 7230.  Example: `example_header_name`
         * 
         * @return builder
         * 
         */
        public Builder header(String header) {
            return header(Output.of(header));
        }

        /**
         * @param httpLargeHeaderSizeInKb (Updatable) The maximum size of each buffer used for reading http client request header. This value indicates the maximum size allowed for each buffer. The allowed values for buffer size are 8, 16, 32 and 64.
         * 
         * @return builder
         * 
         */
        public Builder httpLargeHeaderSizeInKb(@Nullable Output<Integer> httpLargeHeaderSizeInKb) {
            $.httpLargeHeaderSizeInKb = httpLargeHeaderSizeInKb;
            return this;
        }

        /**
         * @param httpLargeHeaderSizeInKb (Updatable) The maximum size of each buffer used for reading http client request header. This value indicates the maximum size allowed for each buffer. The allowed values for buffer size are 8, 16, 32 and 64.
         * 
         * @return builder
         * 
         */
        public Builder httpLargeHeaderSizeInKb(Integer httpLargeHeaderSizeInKb) {
            return httpLargeHeaderSizeInKb(Output.of(httpLargeHeaderSizeInKb));
        }

        /**
         * @param prefix (Updatable) A string to prepend to the header value. The resulting header value must still conform to RFC 7230. With the following exceptions:
         * *  value cannot contain `$`
         * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
         * 
         * @return builder
         * 
         */
        public Builder prefix(@Nullable Output<String> prefix) {
            $.prefix = prefix;
            return this;
        }

        /**
         * @param prefix (Updatable) A string to prepend to the header value. The resulting header value must still conform to RFC 7230. With the following exceptions:
         * *  value cannot contain `$`
         * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
         * 
         * @return builder
         * 
         */
        public Builder prefix(String prefix) {
            return prefix(Output.of(prefix));
        }

        /**
         * @param redirectUri (Updatable) An object that defines the redirect URI applied to the original request. The object property values compose the redirect URI.
         * 
         * @return builder
         * 
         */
        public Builder redirectUri(@Nullable Output<RuleSetItemRedirectUriArgs> redirectUri) {
            $.redirectUri = redirectUri;
            return this;
        }

        /**
         * @param redirectUri (Updatable) An object that defines the redirect URI applied to the original request. The object property values compose the redirect URI.
         * 
         * @return builder
         * 
         */
        public Builder redirectUri(RuleSetItemRedirectUriArgs redirectUri) {
            return redirectUri(Output.of(redirectUri));
        }

        /**
         * @param responseCode (Updatable) The HTTP status code to return when the incoming request is redirected.
         * 
         * @return builder
         * 
         */
        public Builder responseCode(@Nullable Output<Integer> responseCode) {
            $.responseCode = responseCode;
            return this;
        }

        /**
         * @param responseCode (Updatable) The HTTP status code to return when the incoming request is redirected.
         * 
         * @return builder
         * 
         */
        public Builder responseCode(Integer responseCode) {
            return responseCode(Output.of(responseCode));
        }

        /**
         * @param statusCode (Updatable) The HTTP status code to return when the requested HTTP method is not in the list of allowed methods. The associated status line returned with the code is mapped from the standard HTTP specification. The default value is `405 (Method Not Allowed)`.  Example: 403
         * 
         * @return builder
         * 
         */
        public Builder statusCode(@Nullable Output<Integer> statusCode) {
            $.statusCode = statusCode;
            return this;
        }

        /**
         * @param statusCode (Updatable) The HTTP status code to return when the requested HTTP method is not in the list of allowed methods. The associated status line returned with the code is mapped from the standard HTTP specification. The default value is `405 (Method Not Allowed)`.  Example: 403
         * 
         * @return builder
         * 
         */
        public Builder statusCode(Integer statusCode) {
            return statusCode(Output.of(statusCode));
        }

        /**
         * @param suffix (Updatable) A string to append to the header value. The resulting header value must still conform to RFC 7230. With the following exceptions:
         * *  value cannot contain `$`
         * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
         * 
         * @return builder
         * 
         */
        public Builder suffix(@Nullable Output<String> suffix) {
            $.suffix = suffix;
            return this;
        }

        /**
         * @param suffix (Updatable) A string to append to the header value. The resulting header value must still conform to RFC 7230. With the following exceptions:
         * *  value cannot contain `$`
         * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
         * 
         * @return builder
         * 
         */
        public Builder suffix(String suffix) {
            return suffix(Output.of(suffix));
        }

        /**
         * @param value (Updatable) A header value that conforms to RFC 7230. With the following exceptions:
         * *  value cannot contain `$`
         * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
         * 
         * @return builder
         * 
         */
        public Builder value(@Nullable Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value (Updatable) A header value that conforms to RFC 7230. With the following exceptions:
         * *  value cannot contain `$`
         * *  value cannot contain patterns like `{variable_name}`. They are reserved for future extensions. Currently, such values are invalid.
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public RuleSetItemArgs build() {
            $.action = Objects.requireNonNull($.action, "expected parameter 'action' to be non-null");
            return $;
        }
    }

}
