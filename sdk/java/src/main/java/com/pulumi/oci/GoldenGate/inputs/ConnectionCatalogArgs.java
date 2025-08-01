// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GoldenGate.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class ConnectionCatalogArgs extends com.pulumi.resources.ResourceArgs {

    public static final ConnectionCatalogArgs Empty = new ConnectionCatalogArgs();

    /**
     * (Updatable) The active branch of the Nessie catalog from which Iceberg reads and writes table metadata.
     * 
     */
    @Import(name="branch")
    private @Nullable Output<String> branch;

    /**
     * @return (Updatable) The active branch of the Nessie catalog from which Iceberg reads and writes table metadata.
     * 
     */
    public Optional<Output<String>> branch() {
        return Optional.ofNullable(this.branch);
    }

    /**
     * (Updatable) The catalog type.
     * 
     */
    @Import(name="catalogType", required=true)
    private Output<String> catalogType;

    /**
     * @return (Updatable) The catalog type.
     * 
     */
    public Output<String> catalogType() {
        return this.catalogType;
    }

    /**
     * (Updatable) The OAuth client ID used for authentication.
     * 
     */
    @Import(name="clientId")
    private @Nullable Output<String> clientId;

    /**
     * @return (Updatable) The OAuth client ID used for authentication.
     * 
     */
    public Optional<Output<String>> clientId() {
        return Optional.ofNullable(this.clientId);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Secret that stores the password Oracle GoldenGate uses to connect to Snowflake platform.
     * 
     */
    @Import(name="clientSecretSecretId")
    private @Nullable Output<String> clientSecretSecretId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Secret that stores the password Oracle GoldenGate uses to connect to Snowflake platform.
     * 
     */
    public Optional<Output<String>> clientSecretSecretId() {
        return Optional.ofNullable(this.clientSecretSecretId);
    }

    /**
     * (Updatable) The AWS Glue Catalog ID where Iceberg tables are registered.
     * 
     */
    @Import(name="glueId")
    private @Nullable Output<String> glueId;

    /**
     * @return (Updatable) The AWS Glue Catalog ID where Iceberg tables are registered.
     * 
     */
    public Optional<Output<String>> glueId() {
        return Optional.ofNullable(this.glueId);
    }

    /**
     * (Updatable) The catalog name within Polaris where Iceberg tables are registered.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return (Updatable) The catalog name within Polaris where Iceberg tables are registered.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) The Snowflake role used to access Polaris.
     * 
     */
    @Import(name="principalRole")
    private @Nullable Output<String> principalRole;

    /**
     * @return (Updatable) The Snowflake role used to access Polaris.
     * 
     */
    public Optional<Output<String>> principalRole() {
        return Optional.ofNullable(this.principalRole);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Secret that stores the content of the configuration file containing additional properties for the REST catalog. See documentation: https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm
     * 
     */
    @Import(name="propertiesSecretId")
    private @Nullable Output<String> propertiesSecretId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Secret that stores the content of the configuration file containing additional properties for the REST catalog. See documentation: https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm
     * 
     */
    public Optional<Output<String>> propertiesSecretId() {
        return Optional.ofNullable(this.propertiesSecretId);
    }

    /**
     * (Updatable) The URL endpoint for the Polaris API. e.g.: &#39;https://&lt;your-snowflake-account&gt;.snowflakecomputing.com/polaris/api/catalog&#39;
     * 
     */
    @Import(name="uri")
    private @Nullable Output<String> uri;

    /**
     * @return (Updatable) The URL endpoint for the Polaris API. e.g.: &#39;https://&lt;your-snowflake-account&gt;.snowflakecomputing.com/polaris/api/catalog&#39;
     * 
     */
    public Optional<Output<String>> uri() {
        return Optional.ofNullable(this.uri);
    }

    private ConnectionCatalogArgs() {}

    private ConnectionCatalogArgs(ConnectionCatalogArgs $) {
        this.branch = $.branch;
        this.catalogType = $.catalogType;
        this.clientId = $.clientId;
        this.clientSecretSecretId = $.clientSecretSecretId;
        this.glueId = $.glueId;
        this.name = $.name;
        this.principalRole = $.principalRole;
        this.propertiesSecretId = $.propertiesSecretId;
        this.uri = $.uri;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ConnectionCatalogArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ConnectionCatalogArgs $;

        public Builder() {
            $ = new ConnectionCatalogArgs();
        }

        public Builder(ConnectionCatalogArgs defaults) {
            $ = new ConnectionCatalogArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param branch (Updatable) The active branch of the Nessie catalog from which Iceberg reads and writes table metadata.
         * 
         * @return builder
         * 
         */
        public Builder branch(@Nullable Output<String> branch) {
            $.branch = branch;
            return this;
        }

        /**
         * @param branch (Updatable) The active branch of the Nessie catalog from which Iceberg reads and writes table metadata.
         * 
         * @return builder
         * 
         */
        public Builder branch(String branch) {
            return branch(Output.of(branch));
        }

        /**
         * @param catalogType (Updatable) The catalog type.
         * 
         * @return builder
         * 
         */
        public Builder catalogType(Output<String> catalogType) {
            $.catalogType = catalogType;
            return this;
        }

        /**
         * @param catalogType (Updatable) The catalog type.
         * 
         * @return builder
         * 
         */
        public Builder catalogType(String catalogType) {
            return catalogType(Output.of(catalogType));
        }

        /**
         * @param clientId (Updatable) The OAuth client ID used for authentication.
         * 
         * @return builder
         * 
         */
        public Builder clientId(@Nullable Output<String> clientId) {
            $.clientId = clientId;
            return this;
        }

        /**
         * @param clientId (Updatable) The OAuth client ID used for authentication.
         * 
         * @return builder
         * 
         */
        public Builder clientId(String clientId) {
            return clientId(Output.of(clientId));
        }

        /**
         * @param clientSecretSecretId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Secret that stores the password Oracle GoldenGate uses to connect to Snowflake platform.
         * 
         * @return builder
         * 
         */
        public Builder clientSecretSecretId(@Nullable Output<String> clientSecretSecretId) {
            $.clientSecretSecretId = clientSecretSecretId;
            return this;
        }

        /**
         * @param clientSecretSecretId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Secret that stores the password Oracle GoldenGate uses to connect to Snowflake platform.
         * 
         * @return builder
         * 
         */
        public Builder clientSecretSecretId(String clientSecretSecretId) {
            return clientSecretSecretId(Output.of(clientSecretSecretId));
        }

        /**
         * @param glueId (Updatable) The AWS Glue Catalog ID where Iceberg tables are registered.
         * 
         * @return builder
         * 
         */
        public Builder glueId(@Nullable Output<String> glueId) {
            $.glueId = glueId;
            return this;
        }

        /**
         * @param glueId (Updatable) The AWS Glue Catalog ID where Iceberg tables are registered.
         * 
         * @return builder
         * 
         */
        public Builder glueId(String glueId) {
            return glueId(Output.of(glueId));
        }

        /**
         * @param name (Updatable) The catalog name within Polaris where Iceberg tables are registered.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name (Updatable) The catalog name within Polaris where Iceberg tables are registered.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param principalRole (Updatable) The Snowflake role used to access Polaris.
         * 
         * @return builder
         * 
         */
        public Builder principalRole(@Nullable Output<String> principalRole) {
            $.principalRole = principalRole;
            return this;
        }

        /**
         * @param principalRole (Updatable) The Snowflake role used to access Polaris.
         * 
         * @return builder
         * 
         */
        public Builder principalRole(String principalRole) {
            return principalRole(Output.of(principalRole));
        }

        /**
         * @param propertiesSecretId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Secret that stores the content of the configuration file containing additional properties for the REST catalog. See documentation: https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm
         * 
         * @return builder
         * 
         */
        public Builder propertiesSecretId(@Nullable Output<String> propertiesSecretId) {
            $.propertiesSecretId = propertiesSecretId;
            return this;
        }

        /**
         * @param propertiesSecretId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Secret that stores the content of the configuration file containing additional properties for the REST catalog. See documentation: https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm
         * 
         * @return builder
         * 
         */
        public Builder propertiesSecretId(String propertiesSecretId) {
            return propertiesSecretId(Output.of(propertiesSecretId));
        }

        /**
         * @param uri (Updatable) The URL endpoint for the Polaris API. e.g.: &#39;https://&lt;your-snowflake-account&gt;.snowflakecomputing.com/polaris/api/catalog&#39;
         * 
         * @return builder
         * 
         */
        public Builder uri(@Nullable Output<String> uri) {
            $.uri = uri;
            return this;
        }

        /**
         * @param uri (Updatable) The URL endpoint for the Polaris API. e.g.: &#39;https://&lt;your-snowflake-account&gt;.snowflakecomputing.com/polaris/api/catalog&#39;
         * 
         * @return builder
         * 
         */
        public Builder uri(String uri) {
            return uri(Output.of(uri));
        }

        public ConnectionCatalogArgs build() {
            if ($.catalogType == null) {
                throw new MissingRequiredPropertyException("ConnectionCatalogArgs", "catalogType");
            }
            return $;
        }
    }

}
