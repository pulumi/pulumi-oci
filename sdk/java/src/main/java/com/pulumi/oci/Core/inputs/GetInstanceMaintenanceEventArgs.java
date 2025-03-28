// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetInstanceMaintenanceEventArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetInstanceMaintenanceEventArgs Empty = new GetInstanceMaintenanceEventArgs();

    /**
     * The OCID of the instance maintenance event.
     * 
     */
    @Import(name="instanceMaintenanceEventId", required=true)
    private Output<String> instanceMaintenanceEventId;

    /**
     * @return The OCID of the instance maintenance event.
     * 
     */
    public Output<String> instanceMaintenanceEventId() {
        return this.instanceMaintenanceEventId;
    }

    private GetInstanceMaintenanceEventArgs() {}

    private GetInstanceMaintenanceEventArgs(GetInstanceMaintenanceEventArgs $) {
        this.instanceMaintenanceEventId = $.instanceMaintenanceEventId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetInstanceMaintenanceEventArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetInstanceMaintenanceEventArgs $;

        public Builder() {
            $ = new GetInstanceMaintenanceEventArgs();
        }

        public Builder(GetInstanceMaintenanceEventArgs defaults) {
            $ = new GetInstanceMaintenanceEventArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param instanceMaintenanceEventId The OCID of the instance maintenance event.
         * 
         * @return builder
         * 
         */
        public Builder instanceMaintenanceEventId(Output<String> instanceMaintenanceEventId) {
            $.instanceMaintenanceEventId = instanceMaintenanceEventId;
            return this;
        }

        /**
         * @param instanceMaintenanceEventId The OCID of the instance maintenance event.
         * 
         * @return builder
         * 
         */
        public Builder instanceMaintenanceEventId(String instanceMaintenanceEventId) {
            return instanceMaintenanceEventId(Output.of(instanceMaintenanceEventId));
        }

        public GetInstanceMaintenanceEventArgs build() {
            if ($.instanceMaintenanceEventId == null) {
                throw new MissingRequiredPropertyException("GetInstanceMaintenanceEventArgs", "instanceMaintenanceEventId");
            }
            return $;
        }
    }

}
