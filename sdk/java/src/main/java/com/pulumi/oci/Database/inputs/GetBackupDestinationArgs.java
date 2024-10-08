// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetBackupDestinationArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetBackupDestinationArgs Empty = new GetBackupDestinationArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
     * 
     */
    @Import(name="backupDestinationId", required=true)
    private Output<String> backupDestinationId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
     * 
     */
    public Output<String> backupDestinationId() {
        return this.backupDestinationId;
    }

    private GetBackupDestinationArgs() {}

    private GetBackupDestinationArgs(GetBackupDestinationArgs $) {
        this.backupDestinationId = $.backupDestinationId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetBackupDestinationArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetBackupDestinationArgs $;

        public Builder() {
            $ = new GetBackupDestinationArgs();
        }

        public Builder(GetBackupDestinationArgs defaults) {
            $ = new GetBackupDestinationArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param backupDestinationId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
         * 
         * @return builder
         * 
         */
        public Builder backupDestinationId(Output<String> backupDestinationId) {
            $.backupDestinationId = backupDestinationId;
            return this;
        }

        /**
         * @param backupDestinationId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the backup destination.
         * 
         * @return builder
         * 
         */
        public Builder backupDestinationId(String backupDestinationId) {
            return backupDestinationId(Output.of(backupDestinationId));
        }

        public GetBackupDestinationArgs build() {
            if ($.backupDestinationId == null) {
                throw new MissingRequiredPropertyException("GetBackupDestinationArgs", "backupDestinationId");
            }
            return $;
        }
    }

}
