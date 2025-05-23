// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.ApmSynthetics.inputs.ConfigConfigurationReqAuthenticationDetailsAuthHeaderArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConfigConfigurationReqAuthenticationDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConfigConfigurationReqAuthenticationDetailsArgs Empty = new ConfigConfigurationReqAuthenticationDetailsArgs();

    /**
     * (Updatable) List of authentication headers. Example: `[{&#34;headerName&#34;: &#34;content-type&#34;, &#34;headerValue&#34;:&#34;json&#34;}]`
     * 
     */
    @Import(name="authHeaders")
    private @Nullable Output<List<ConfigConfigurationReqAuthenticationDetailsAuthHeaderArgs>> authHeaders;

    /**
     * @return (Updatable) List of authentication headers. Example: `[{&#34;headerName&#34;: &#34;content-type&#34;, &#34;headerValue&#34;:&#34;json&#34;}]`
     * 
     */
    public Optional<Output<List<ConfigConfigurationReqAuthenticationDetailsAuthHeaderArgs>>> authHeaders() {
        return Optional.ofNullable(this.authHeaders);
    }

    /**
     * (Updatable) Request method.
     * 
     */
    @Import(name="authRequestMethod")
    private @Nullable Output<String> authRequestMethod;

    /**
     * @return (Updatable) Request method.
     * 
     */
    public Optional<Output<String>> authRequestMethod() {
        return Optional.ofNullable(this.authRequestMethod);
    }

    /**
     * (Updatable) Request post body.
     * 
     */
    @Import(name="authRequestPostBody")
    private @Nullable Output<String> authRequestPostBody;

    /**
     * @return (Updatable) Request post body.
     * 
     */
    public Optional<Output<String>> authRequestPostBody() {
        return Optional.ofNullable(this.authRequestPostBody);
    }

    /**
     * (Updatable) Authentication token.
     * 
     */
    @Import(name="authToken")
    private @Nullable Output<String> authToken;

    /**
     * @return (Updatable) Authentication token.
     * 
     */
    public Optional<Output<String>> authToken() {
        return Optional.ofNullable(this.authToken);
    }

    /**
     * (Updatable) URL to get authentication token.
     * 
     */
    @Import(name="authUrl")
    private @Nullable Output<String> authUrl;

    /**
     * @return (Updatable) URL to get authentication token.
     * 
     */
    public Optional<Output<String>> authUrl() {
        return Optional.ofNullable(this.authUrl);
    }

    /**
     * (Updatable) User name for authentication.
     * 
     */
    @Import(name="authUserName")
    private @Nullable Output<String> authUserName;

    /**
     * @return (Updatable) User name for authentication.
     * 
     */
    public Optional<Output<String>> authUserName() {
        return Optional.ofNullable(this.authUserName);
    }

    /**
     * (Updatable) User password for authentication.
     * 
     */
    @Import(name="authUserPassword")
    private @Nullable Output<String> authUserPassword;

    /**
     * @return (Updatable) User password for authentication.
     * 
     */
    public Optional<Output<String>> authUserPassword() {
        return Optional.ofNullable(this.authUserPassword);
    }

    /**
     * (Updatable) Request HTTP OAuth scheme.
     * 
     */
    @Import(name="oauthScheme")
    private @Nullable Output<String> oauthScheme;

    /**
     * @return (Updatable) Request HTTP OAuth scheme.
     * 
     */
    public Optional<Output<String>> oauthScheme() {
        return Optional.ofNullable(this.oauthScheme);
    }

    private ConfigConfigurationReqAuthenticationDetailsArgs() {}

    private ConfigConfigurationReqAuthenticationDetailsArgs(ConfigConfigurationReqAuthenticationDetailsArgs $) {
        this.authHeaders = $.authHeaders;
        this.authRequestMethod = $.authRequestMethod;
        this.authRequestPostBody = $.authRequestPostBody;
        this.authToken = $.authToken;
        this.authUrl = $.authUrl;
        this.authUserName = $.authUserName;
        this.authUserPassword = $.authUserPassword;
        this.oauthScheme = $.oauthScheme;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConfigConfigurationReqAuthenticationDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConfigConfigurationReqAuthenticationDetailsArgs $;

        public Builder() {
            $ = new ConfigConfigurationReqAuthenticationDetailsArgs();
        }

        public Builder(ConfigConfigurationReqAuthenticationDetailsArgs defaults) {
            $ = new ConfigConfigurationReqAuthenticationDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param authHeaders (Updatable) List of authentication headers. Example: `[{&#34;headerName&#34;: &#34;content-type&#34;, &#34;headerValue&#34;:&#34;json&#34;}]`
         * 
         * @return builder
         * 
         */
        public Builder authHeaders(@Nullable Output<List<ConfigConfigurationReqAuthenticationDetailsAuthHeaderArgs>> authHeaders) {
            $.authHeaders = authHeaders;
            return this;
        }

        /**
         * @param authHeaders (Updatable) List of authentication headers. Example: `[{&#34;headerName&#34;: &#34;content-type&#34;, &#34;headerValue&#34;:&#34;json&#34;}]`
         * 
         * @return builder
         * 
         */
        public Builder authHeaders(List<ConfigConfigurationReqAuthenticationDetailsAuthHeaderArgs> authHeaders) {
            return authHeaders(Output.of(authHeaders));
        }

        /**
         * @param authHeaders (Updatable) List of authentication headers. Example: `[{&#34;headerName&#34;: &#34;content-type&#34;, &#34;headerValue&#34;:&#34;json&#34;}]`
         * 
         * @return builder
         * 
         */
        public Builder authHeaders(ConfigConfigurationReqAuthenticationDetailsAuthHeaderArgs... authHeaders) {
            return authHeaders(List.of(authHeaders));
        }

        /**
         * @param authRequestMethod (Updatable) Request method.
         * 
         * @return builder
         * 
         */
        public Builder authRequestMethod(@Nullable Output<String> authRequestMethod) {
            $.authRequestMethod = authRequestMethod;
            return this;
        }

        /**
         * @param authRequestMethod (Updatable) Request method.
         * 
         * @return builder
         * 
         */
        public Builder authRequestMethod(String authRequestMethod) {
            return authRequestMethod(Output.of(authRequestMethod));
        }

        /**
         * @param authRequestPostBody (Updatable) Request post body.
         * 
         * @return builder
         * 
         */
        public Builder authRequestPostBody(@Nullable Output<String> authRequestPostBody) {
            $.authRequestPostBody = authRequestPostBody;
            return this;
        }

        /**
         * @param authRequestPostBody (Updatable) Request post body.
         * 
         * @return builder
         * 
         */
        public Builder authRequestPostBody(String authRequestPostBody) {
            return authRequestPostBody(Output.of(authRequestPostBody));
        }

        /**
         * @param authToken (Updatable) Authentication token.
         * 
         * @return builder
         * 
         */
        public Builder authToken(@Nullable Output<String> authToken) {
            $.authToken = authToken;
            return this;
        }

        /**
         * @param authToken (Updatable) Authentication token.
         * 
         * @return builder
         * 
         */
        public Builder authToken(String authToken) {
            return authToken(Output.of(authToken));
        }

        /**
         * @param authUrl (Updatable) URL to get authentication token.
         * 
         * @return builder
         * 
         */
        public Builder authUrl(@Nullable Output<String> authUrl) {
            $.authUrl = authUrl;
            return this;
        }

        /**
         * @param authUrl (Updatable) URL to get authentication token.
         * 
         * @return builder
         * 
         */
        public Builder authUrl(String authUrl) {
            return authUrl(Output.of(authUrl));
        }

        /**
         * @param authUserName (Updatable) User name for authentication.
         * 
         * @return builder
         * 
         */
        public Builder authUserName(@Nullable Output<String> authUserName) {
            $.authUserName = authUserName;
            return this;
        }

        /**
         * @param authUserName (Updatable) User name for authentication.
         * 
         * @return builder
         * 
         */
        public Builder authUserName(String authUserName) {
            return authUserName(Output.of(authUserName));
        }

        /**
         * @param authUserPassword (Updatable) User password for authentication.
         * 
         * @return builder
         * 
         */
        public Builder authUserPassword(@Nullable Output<String> authUserPassword) {
            $.authUserPassword = authUserPassword;
            return this;
        }

        /**
         * @param authUserPassword (Updatable) User password for authentication.
         * 
         * @return builder
         * 
         */
        public Builder authUserPassword(String authUserPassword) {
            return authUserPassword(Output.of(authUserPassword));
        }

        /**
         * @param oauthScheme (Updatable) Request HTTP OAuth scheme.
         * 
         * @return builder
         * 
         */
        public Builder oauthScheme(@Nullable Output<String> oauthScheme) {
            $.oauthScheme = oauthScheme;
            return this;
        }

        /**
         * @param oauthScheme (Updatable) Request HTTP OAuth scheme.
         * 
         * @return builder
         * 
         */
        public Builder oauthScheme(String oauthScheme) {
            return oauthScheme(Output.of(oauthScheme));
        }

        public ConfigConfigurationReqAuthenticationDetailsArgs build() {
            return $;
        }
    }

}
