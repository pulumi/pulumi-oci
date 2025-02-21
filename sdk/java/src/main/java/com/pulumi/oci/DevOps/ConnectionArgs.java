// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DevOps.inputs.ConnectionTlsVerifyConfigArgs;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConnectionArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConnectionArgs Empty = new ConnectionArgs();

    /**
     * (Updatable) The OCID of personal access token saved in secret store.
     * 
     */
    @Import(name="accessToken")
    private @Nullable Output<String> accessToken;

    /**
     * @return (Updatable) The OCID of personal access token saved in secret store.
     * 
     */
    public Optional<Output<String>> accessToken() {
        return Optional.ofNullable(this.accessToken);
    }

    /**
     * (Updatable) OCID of personal Bitbucket Cloud AppPassword saved in secret store
     * 
     */
    @Import(name="appPassword")
    private @Nullable Output<String> appPassword;

    /**
     * @return (Updatable) OCID of personal Bitbucket Cloud AppPassword saved in secret store
     * 
     */
    public Optional<Output<String>> appPassword() {
        return Optional.ofNullable(this.appPassword);
    }

    /**
     * (Updatable) The Base URL of the hosted BitbucketServer.
     * 
     */
    @Import(name="baseUrl")
    private @Nullable Output<String> baseUrl;

    /**
     * @return (Updatable) The Base URL of the hosted BitbucketServer.
     * 
     */
    public Optional<Output<String>> baseUrl() {
        return Optional.ofNullable(this.baseUrl);
    }

    /**
     * (Updatable) The type of connection.
     * 
     */
    @Import(name="connectionType", required=true)
    private Output<String> connectionType;

    /**
     * @return (Updatable) The type of connection.
     * 
     */
    public Output<String> connectionType() {
        return this.connectionType;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Optional description about the connection.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) Optional description about the connection.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Optional connection display name. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) Optional connection display name. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The OCID of the DevOps project.
     * 
     */
    @Import(name="projectId", required=true)
    private Output<String> projectId;

    /**
     * @return The OCID of the DevOps project.
     * 
     */
    public Output<String> projectId() {
        return this.projectId;
    }

    /**
     * (Updatable) TLS configuration used by build service to verify TLS connection.
     * 
     */
    @Import(name="tlsVerifyConfig")
    private @Nullable Output<ConnectionTlsVerifyConfigArgs> tlsVerifyConfig;

    /**
     * @return (Updatable) TLS configuration used by build service to verify TLS connection.
     * 
     */
    public Optional<Output<ConnectionTlsVerifyConfigArgs>> tlsVerifyConfig() {
        return Optional.ofNullable(this.tlsVerifyConfig);
    }

    /**
     * (Updatable) Public Bitbucket Cloud Username in plain text(not more than 30 characters)
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="username")
    private @Nullable Output<String> username;

    /**
     * @return (Updatable) Public Bitbucket Cloud Username in plain text(not more than 30 characters)
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> username() {
        return Optional.ofNullable(this.username);
    }

    private ConnectionArgs() {}

    private ConnectionArgs(ConnectionArgs $) {
        this.accessToken = $.accessToken;
        this.appPassword = $.appPassword;
        this.baseUrl = $.baseUrl;
        this.connectionType = $.connectionType;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.projectId = $.projectId;
        this.tlsVerifyConfig = $.tlsVerifyConfig;
        this.username = $.username;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConnectionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConnectionArgs $;

        public Builder() {
            $ = new ConnectionArgs();
        }

        public Builder(ConnectionArgs defaults) {
            $ = new ConnectionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param accessToken (Updatable) The OCID of personal access token saved in secret store.
         * 
         * @return builder
         * 
         */
        public Builder accessToken(@Nullable Output<String> accessToken) {
            $.accessToken = accessToken;
            return this;
        }

        /**
         * @param accessToken (Updatable) The OCID of personal access token saved in secret store.
         * 
         * @return builder
         * 
         */
        public Builder accessToken(String accessToken) {
            return accessToken(Output.of(accessToken));
        }

        /**
         * @param appPassword (Updatable) OCID of personal Bitbucket Cloud AppPassword saved in secret store
         * 
         * @return builder
         * 
         */
        public Builder appPassword(@Nullable Output<String> appPassword) {
            $.appPassword = appPassword;
            return this;
        }

        /**
         * @param appPassword (Updatable) OCID of personal Bitbucket Cloud AppPassword saved in secret store
         * 
         * @return builder
         * 
         */
        public Builder appPassword(String appPassword) {
            return appPassword(Output.of(appPassword));
        }

        /**
         * @param baseUrl (Updatable) The Base URL of the hosted BitbucketServer.
         * 
         * @return builder
         * 
         */
        public Builder baseUrl(@Nullable Output<String> baseUrl) {
            $.baseUrl = baseUrl;
            return this;
        }

        /**
         * @param baseUrl (Updatable) The Base URL of the hosted BitbucketServer.
         * 
         * @return builder
         * 
         */
        public Builder baseUrl(String baseUrl) {
            return baseUrl(Output.of(baseUrl));
        }

        /**
         * @param connectionType (Updatable) The type of connection.
         * 
         * @return builder
         * 
         */
        public Builder connectionType(Output<String> connectionType) {
            $.connectionType = connectionType;
            return this;
        }

        /**
         * @param connectionType (Updatable) The type of connection.
         * 
         * @return builder
         * 
         */
        public Builder connectionType(String connectionType) {
            return connectionType(Output.of(connectionType));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) Optional description about the connection.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) Optional description about the connection.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) Optional connection display name. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Optional connection display name. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param projectId The OCID of the DevOps project.
         * 
         * @return builder
         * 
         */
        public Builder projectId(Output<String> projectId) {
            $.projectId = projectId;
            return this;
        }

        /**
         * @param projectId The OCID of the DevOps project.
         * 
         * @return builder
         * 
         */
        public Builder projectId(String projectId) {
            return projectId(Output.of(projectId));
        }

        /**
         * @param tlsVerifyConfig (Updatable) TLS configuration used by build service to verify TLS connection.
         * 
         * @return builder
         * 
         */
        public Builder tlsVerifyConfig(@Nullable Output<ConnectionTlsVerifyConfigArgs> tlsVerifyConfig) {
            $.tlsVerifyConfig = tlsVerifyConfig;
            return this;
        }

        /**
         * @param tlsVerifyConfig (Updatable) TLS configuration used by build service to verify TLS connection.
         * 
         * @return builder
         * 
         */
        public Builder tlsVerifyConfig(ConnectionTlsVerifyConfigArgs tlsVerifyConfig) {
            return tlsVerifyConfig(Output.of(tlsVerifyConfig));
        }

        /**
         * @param username (Updatable) Public Bitbucket Cloud Username in plain text(not more than 30 characters)
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder username(@Nullable Output<String> username) {
            $.username = username;
            return this;
        }

        /**
         * @param username (Updatable) Public Bitbucket Cloud Username in plain text(not more than 30 characters)
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder username(String username) {
            return username(Output.of(username));
        }

        public ConnectionArgs build() {
            if ($.connectionType == null) {
                throw new MissingRequiredPropertyException("ConnectionArgs", "connectionType");
            }
            if ($.projectId == null) {
                throw new MissingRequiredPropertyException("ConnectionArgs", "projectId");
            }
            return $;
        }
    }

}
