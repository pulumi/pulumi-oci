// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GenerativeAi.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class AgentToolToolConfigDatabaseConnectionArgs extends com.pulumi.resources.ResourceArgs {

    public static final AgentToolToolConfigDatabaseConnectionArgs Empty = new AgentToolToolConfigDatabaseConnectionArgs();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools Connection.
     * 
     */
    @Import(name="connectionId", required=true)
    private Output<String> connectionId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools Connection.
     * 
     */
    public Output<String> connectionId() {
        return this.connectionId;
    }

    /**
     * (Updatable) The type of Database connection. The allowed values are:
     * * `DATABASE_TOOL_CONNECTION`: This allows the service to connect to a vector store via a Database Tools Connection.
     * 
     */
    @Import(name="connectionType", required=true)
    private Output<String> connectionType;

    /**
     * @return (Updatable) The type of Database connection. The allowed values are:
     * * `DATABASE_TOOL_CONNECTION`: This allows the service to connect to a vector store via a Database Tools Connection.
     * 
     */
    public Output<String> connectionType() {
        return this.connectionType;
    }

    private AgentToolToolConfigDatabaseConnectionArgs() {}

    private AgentToolToolConfigDatabaseConnectionArgs(AgentToolToolConfigDatabaseConnectionArgs $) {
        this.connectionId = $.connectionId;
        this.connectionType = $.connectionType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AgentToolToolConfigDatabaseConnectionArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AgentToolToolConfigDatabaseConnectionArgs $;

        public Builder() {
            $ = new AgentToolToolConfigDatabaseConnectionArgs();
        }

        public Builder(AgentToolToolConfigDatabaseConnectionArgs defaults) {
            $ = new AgentToolToolConfigDatabaseConnectionArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param connectionId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools Connection.
         * 
         * @return builder
         * 
         */
        public Builder connectionId(Output<String> connectionId) {
            $.connectionId = connectionId;
            return this;
        }

        /**
         * @param connectionId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Database Tools Connection.
         * 
         * @return builder
         * 
         */
        public Builder connectionId(String connectionId) {
            return connectionId(Output.of(connectionId));
        }

        /**
         * @param connectionType (Updatable) The type of Database connection. The allowed values are:
         * * `DATABASE_TOOL_CONNECTION`: This allows the service to connect to a vector store via a Database Tools Connection.
         * 
         * @return builder
         * 
         */
        public Builder connectionType(Output<String> connectionType) {
            $.connectionType = connectionType;
            return this;
        }

        /**
         * @param connectionType (Updatable) The type of Database connection. The allowed values are:
         * * `DATABASE_TOOL_CONNECTION`: This allows the service to connect to a vector store via a Database Tools Connection.
         * 
         * @return builder
         * 
         */
        public Builder connectionType(String connectionType) {
            return connectionType(Output.of(connectionType));
        }

        public AgentToolToolConfigDatabaseConnectionArgs build() {
            if ($.connectionId == null) {
                throw new MissingRequiredPropertyException("AgentToolToolConfigDatabaseConnectionArgs", "connectionId");
            }
            if ($.connectionType == null) {
                throw new MissingRequiredPropertyException("AgentToolToolConfigDatabaseConnectionArgs", "connectionType");
            }
            return $;
        }
    }

}
