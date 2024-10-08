// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetAutonomousDatabaseBackupArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAutonomousDatabaseBackupArgs Empty = new GetAutonomousDatabaseBackupArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database backup.
     * 
     */
    @Import(name="autonomousDatabaseBackupId", required=true)
    private Output<String> autonomousDatabaseBackupId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database backup.
     * 
     */
    public Output<String> autonomousDatabaseBackupId() {
        return this.autonomousDatabaseBackupId;
    }

    private GetAutonomousDatabaseBackupArgs() {}

    private GetAutonomousDatabaseBackupArgs(GetAutonomousDatabaseBackupArgs $) {
        this.autonomousDatabaseBackupId = $.autonomousDatabaseBackupId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAutonomousDatabaseBackupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAutonomousDatabaseBackupArgs $;

        public Builder() {
            $ = new GetAutonomousDatabaseBackupArgs();
        }

        public Builder(GetAutonomousDatabaseBackupArgs defaults) {
            $ = new GetAutonomousDatabaseBackupArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param autonomousDatabaseBackupId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database backup.
         * 
         * @return builder
         * 
         */
        public Builder autonomousDatabaseBackupId(Output<String> autonomousDatabaseBackupId) {
            $.autonomousDatabaseBackupId = autonomousDatabaseBackupId;
            return this;
        }

        /**
         * @param autonomousDatabaseBackupId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Autonomous Database backup.
         * 
         * @return builder
         * 
         */
        public Builder autonomousDatabaseBackupId(String autonomousDatabaseBackupId) {
            return autonomousDatabaseBackupId(Output.of(autonomousDatabaseBackupId));
        }

        public GetAutonomousDatabaseBackupArgs build() {
            if ($.autonomousDatabaseBackupId == null) {
                throw new MissingRequiredPropertyException("GetAutonomousDatabaseBackupArgs", "autonomousDatabaseBackupId");
            }
            return $;
        }
    }

}
