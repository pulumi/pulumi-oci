// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseTools.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetDatabaseToolsPrivateEndpointPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDatabaseToolsPrivateEndpointPlainArgs Empty = new GetDatabaseToolsPrivateEndpointPlainArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Database Tools private endpoint.
     * 
     */
    @Import(name="databaseToolsPrivateEndpointId", required=true)
    private String databaseToolsPrivateEndpointId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Database Tools private endpoint.
     * 
     */
    public String databaseToolsPrivateEndpointId() {
        return this.databaseToolsPrivateEndpointId;
    }

    private GetDatabaseToolsPrivateEndpointPlainArgs() {}

    private GetDatabaseToolsPrivateEndpointPlainArgs(GetDatabaseToolsPrivateEndpointPlainArgs $) {
        this.databaseToolsPrivateEndpointId = $.databaseToolsPrivateEndpointId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDatabaseToolsPrivateEndpointPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDatabaseToolsPrivateEndpointPlainArgs $;

        public Builder() {
            $ = new GetDatabaseToolsPrivateEndpointPlainArgs();
        }

        public Builder(GetDatabaseToolsPrivateEndpointPlainArgs defaults) {
            $ = new GetDatabaseToolsPrivateEndpointPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param databaseToolsPrivateEndpointId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of a Database Tools private endpoint.
         * 
         * @return builder
         * 
         */
        public Builder databaseToolsPrivateEndpointId(String databaseToolsPrivateEndpointId) {
            $.databaseToolsPrivateEndpointId = databaseToolsPrivateEndpointId;
            return this;
        }

        public GetDatabaseToolsPrivateEndpointPlainArgs build() {
            $.databaseToolsPrivateEndpointId = Objects.requireNonNull($.databaseToolsPrivateEndpointId, "expected parameter 'databaseToolsPrivateEndpointId' to be non-null");
            return $;
        }
    }

}