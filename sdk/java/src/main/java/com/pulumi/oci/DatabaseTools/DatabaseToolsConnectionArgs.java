// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DatabaseTools.inputs.DatabaseToolsConnectionKeyStoreArgs;
import com.pulumi.oci.DatabaseTools.inputs.DatabaseToolsConnectionRelatedResourceArgs;
import com.pulumi.oci.DatabaseTools.inputs.DatabaseToolsConnectionUserPasswordArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DatabaseToolsConnectionArgs extends com.pulumi.resources.ResourceArgs {

    public static final DatabaseToolsConnectionArgs Empty = new DatabaseToolsConnectionArgs();

    /**
     * (Updatable) Advanced connection properties key-value pair (e.g., oracle.net.ssl_server_dn_match).
     * 
     */
    @Import(name="advancedProperties")
    private @Nullable Output<Map<String,Object>> advancedProperties;

    /**
     * @return (Updatable) Advanced connection properties key-value pair (e.g., oracle.net.ssl_server_dn_match).
     * 
     */
    public Optional<Output<Map<String,Object>>> advancedProperties() {
        return Optional.ofNullable(this.advancedProperties);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the containing Compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the containing Compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Connect descriptor or Easy Connect Naming method to connect to the database.
     * 
     */
    @Import(name="connectionString")
    private @Nullable Output<String> connectionString;

    /**
     * @return (Updatable) Connect descriptor or Easy Connect Naming method to connect to the database.
     * 
     */
    public Optional<Output<String>> connectionString() {
        return Optional.ofNullable(this.connectionString);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Oracle wallet or Java Keystores containing trusted certificates for authenticating the server&#39;s public certificate and the client private key and associated certificates required for client authentication.
     * 
     */
    @Import(name="keyStores")
    private @Nullable Output<List<DatabaseToolsConnectionKeyStoreArgs>> keyStores;

    /**
     * @return (Updatable) Oracle wallet or Java Keystores containing trusted certificates for authenticating the server&#39;s public certificate and the client private key and associated certificates required for client authentication.
     * 
     */
    public Optional<Output<List<DatabaseToolsConnectionKeyStoreArgs>>> keyStores() {
        return Optional.ofNullable(this.keyStores);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DatabaseToolsPrivateEndpoint used to access the database in the Customer VCN.
     * 
     */
    @Import(name="privateEndpointId")
    private @Nullable Output<String> privateEndpointId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DatabaseToolsPrivateEndpoint used to access the database in the Customer VCN.
     * 
     */
    public Optional<Output<String>> privateEndpointId() {
        return Optional.ofNullable(this.privateEndpointId);
    }

    /**
     * (Updatable) The related resource
     * 
     */
    @Import(name="relatedResource")
    private @Nullable Output<DatabaseToolsConnectionRelatedResourceArgs> relatedResource;

    /**
     * @return (Updatable) The related resource
     * 
     */
    public Optional<Output<DatabaseToolsConnectionRelatedResourceArgs>> relatedResource() {
        return Optional.ofNullable(this.relatedResource);
    }

    /**
     * (Updatable) The DatabaseToolsConnection type.
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return (Updatable) The DatabaseToolsConnection type.
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    /**
     * (Updatable) Database user name.
     * 
     */
    @Import(name="userName")
    private @Nullable Output<String> userName;

    /**
     * @return (Updatable) Database user name.
     * 
     */
    public Optional<Output<String>> userName() {
        return Optional.ofNullable(this.userName);
    }

    /**
     * (Updatable) The user password.
     * 
     */
    @Import(name="userPassword")
    private @Nullable Output<DatabaseToolsConnectionUserPasswordArgs> userPassword;

    /**
     * @return (Updatable) The user password.
     * 
     */
    public Optional<Output<DatabaseToolsConnectionUserPasswordArgs>> userPassword() {
        return Optional.ofNullable(this.userPassword);
    }

    private DatabaseToolsConnectionArgs() {}

    private DatabaseToolsConnectionArgs(DatabaseToolsConnectionArgs $) {
        this.advancedProperties = $.advancedProperties;
        this.compartmentId = $.compartmentId;
        this.connectionString = $.connectionString;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.keyStores = $.keyStores;
        this.privateEndpointId = $.privateEndpointId;
        this.relatedResource = $.relatedResource;
        this.type = $.type;
        this.userName = $.userName;
        this.userPassword = $.userPassword;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DatabaseToolsConnectionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DatabaseToolsConnectionArgs $;

        public Builder() {
            $ = new DatabaseToolsConnectionArgs();
        }

        public Builder(DatabaseToolsConnectionArgs defaults) {
            $ = new DatabaseToolsConnectionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param advancedProperties (Updatable) Advanced connection properties key-value pair (e.g., oracle.net.ssl_server_dn_match).
         * 
         * @return builder
         * 
         */
        public Builder advancedProperties(@Nullable Output<Map<String,Object>> advancedProperties) {
            $.advancedProperties = advancedProperties;
            return this;
        }

        /**
         * @param advancedProperties (Updatable) Advanced connection properties key-value pair (e.g., oracle.net.ssl_server_dn_match).
         * 
         * @return builder
         * 
         */
        public Builder advancedProperties(Map<String,Object> advancedProperties) {
            return advancedProperties(Output.of(advancedProperties));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the containing Compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the containing Compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param connectionString (Updatable) Connect descriptor or Easy Connect Naming method to connect to the database.
         * 
         * @return builder
         * 
         */
        public Builder connectionString(@Nullable Output<String> connectionString) {
            $.connectionString = connectionString;
            return this;
        }

        /**
         * @param connectionString (Updatable) Connect descriptor or Easy Connect Naming method to connect to the database.
         * 
         * @return builder
         * 
         */
        public Builder connectionString(String connectionString) {
            return connectionString(Output.of(connectionString));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param keyStores (Updatable) Oracle wallet or Java Keystores containing trusted certificates for authenticating the server&#39;s public certificate and the client private key and associated certificates required for client authentication.
         * 
         * @return builder
         * 
         */
        public Builder keyStores(@Nullable Output<List<DatabaseToolsConnectionKeyStoreArgs>> keyStores) {
            $.keyStores = keyStores;
            return this;
        }

        /**
         * @param keyStores (Updatable) Oracle wallet or Java Keystores containing trusted certificates for authenticating the server&#39;s public certificate and the client private key and associated certificates required for client authentication.
         * 
         * @return builder
         * 
         */
        public Builder keyStores(List<DatabaseToolsConnectionKeyStoreArgs> keyStores) {
            return keyStores(Output.of(keyStores));
        }

        /**
         * @param keyStores (Updatable) Oracle wallet or Java Keystores containing trusted certificates for authenticating the server&#39;s public certificate and the client private key and associated certificates required for client authentication.
         * 
         * @return builder
         * 
         */
        public Builder keyStores(DatabaseToolsConnectionKeyStoreArgs... keyStores) {
            return keyStores(List.of(keyStores));
        }

        /**
         * @param privateEndpointId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DatabaseToolsPrivateEndpoint used to access the database in the Customer VCN.
         * 
         * @return builder
         * 
         */
        public Builder privateEndpointId(@Nullable Output<String> privateEndpointId) {
            $.privateEndpointId = privateEndpointId;
            return this;
        }

        /**
         * @param privateEndpointId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DatabaseToolsPrivateEndpoint used to access the database in the Customer VCN.
         * 
         * @return builder
         * 
         */
        public Builder privateEndpointId(String privateEndpointId) {
            return privateEndpointId(Output.of(privateEndpointId));
        }

        /**
         * @param relatedResource (Updatable) The related resource
         * 
         * @return builder
         * 
         */
        public Builder relatedResource(@Nullable Output<DatabaseToolsConnectionRelatedResourceArgs> relatedResource) {
            $.relatedResource = relatedResource;
            return this;
        }

        /**
         * @param relatedResource (Updatable) The related resource
         * 
         * @return builder
         * 
         */
        public Builder relatedResource(DatabaseToolsConnectionRelatedResourceArgs relatedResource) {
            return relatedResource(Output.of(relatedResource));
        }

        /**
         * @param type (Updatable) The DatabaseToolsConnection type.
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) The DatabaseToolsConnection type.
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        /**
         * @param userName (Updatable) Database user name.
         * 
         * @return builder
         * 
         */
        public Builder userName(@Nullable Output<String> userName) {
            $.userName = userName;
            return this;
        }

        /**
         * @param userName (Updatable) Database user name.
         * 
         * @return builder
         * 
         */
        public Builder userName(String userName) {
            return userName(Output.of(userName));
        }

        /**
         * @param userPassword (Updatable) The user password.
         * 
         * @return builder
         * 
         */
        public Builder userPassword(@Nullable Output<DatabaseToolsConnectionUserPasswordArgs> userPassword) {
            $.userPassword = userPassword;
            return this;
        }

        /**
         * @param userPassword (Updatable) The user password.
         * 
         * @return builder
         * 
         */
        public Builder userPassword(DatabaseToolsConnectionUserPasswordArgs userPassword) {
            return userPassword(Output.of(userPassword));
        }

        public DatabaseToolsConnectionArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.type = Objects.requireNonNull($.type, "expected parameter 'type' to be non-null");
            return $;
        }
    }

}
