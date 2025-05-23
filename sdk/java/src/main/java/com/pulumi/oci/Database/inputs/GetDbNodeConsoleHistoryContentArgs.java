// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetDbNodeConsoleHistoryContentArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDbNodeConsoleHistoryContentArgs Empty = new GetDbNodeConsoleHistoryContentArgs();

    /**
     * The OCID of the console history.
     * 
     */
    @Import(name="consoleHistoryId", required=true)
    private Output<String> consoleHistoryId;

    /**
     * @return The OCID of the console history.
     * 
     */
    public Output<String> consoleHistoryId() {
        return this.consoleHistoryId;
    }

    /**
     * The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    @Import(name="dbNodeId", required=true)
    private Output<String> dbNodeId;

    /**
     * @return The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
     * 
     */
    public Output<String> dbNodeId() {
        return this.dbNodeId;
    }

    private GetDbNodeConsoleHistoryContentArgs() {}

    private GetDbNodeConsoleHistoryContentArgs(GetDbNodeConsoleHistoryContentArgs $) {
        this.consoleHistoryId = $.consoleHistoryId;
        this.dbNodeId = $.dbNodeId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDbNodeConsoleHistoryContentArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDbNodeConsoleHistoryContentArgs $;

        public Builder() {
            $ = new GetDbNodeConsoleHistoryContentArgs();
        }

        public Builder(GetDbNodeConsoleHistoryContentArgs defaults) {
            $ = new GetDbNodeConsoleHistoryContentArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param consoleHistoryId The OCID of the console history.
         * 
         * @return builder
         * 
         */
        public Builder consoleHistoryId(Output<String> consoleHistoryId) {
            $.consoleHistoryId = consoleHistoryId;
            return this;
        }

        /**
         * @param consoleHistoryId The OCID of the console history.
         * 
         * @return builder
         * 
         */
        public Builder consoleHistoryId(String consoleHistoryId) {
            return consoleHistoryId(Output.of(consoleHistoryId));
        }

        /**
         * @param dbNodeId The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbNodeId(Output<String> dbNodeId) {
            $.dbNodeId = dbNodeId;
            return this;
        }

        /**
         * @param dbNodeId The database node [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
         * 
         * @return builder
         * 
         */
        public Builder dbNodeId(String dbNodeId) {
            return dbNodeId(Output.of(dbNodeId));
        }

        public GetDbNodeConsoleHistoryContentArgs build() {
            if ($.consoleHistoryId == null) {
                throw new MissingRequiredPropertyException("GetDbNodeConsoleHistoryContentArgs", "consoleHistoryId");
            }
            if ($.dbNodeId == null) {
                throw new MissingRequiredPropertyException("GetDbNodeConsoleHistoryContentArgs", "dbNodeId");
            }
            return $;
        }
    }

}
