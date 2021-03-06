// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.GetVolumeBackupPoliciesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetVolumeBackupPoliciesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetVolumeBackupPoliciesArgs Empty = new GetVolumeBackupPoliciesArgs();

    /**
     * The OCID of the compartment. If no compartment is specified, the Oracle defined backup policies are listed.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment. If no compartment is specified, the Oracle defined backup policies are listed.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetVolumeBackupPoliciesFilterArgs>> filters;

    public Optional<Output<List<GetVolumeBackupPoliciesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    private GetVolumeBackupPoliciesArgs() {}

    private GetVolumeBackupPoliciesArgs(GetVolumeBackupPoliciesArgs $) {
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetVolumeBackupPoliciesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetVolumeBackupPoliciesArgs $;

        public Builder() {
            $ = new GetVolumeBackupPoliciesArgs();
        }

        public Builder(GetVolumeBackupPoliciesArgs defaults) {
            $ = new GetVolumeBackupPoliciesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment. If no compartment is specified, the Oracle defined backup policies are listed.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment. If no compartment is specified, the Oracle defined backup policies are listed.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder filters(@Nullable Output<List<GetVolumeBackupPoliciesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetVolumeBackupPoliciesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetVolumeBackupPoliciesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        public GetVolumeBackupPoliciesArgs build() {
            return $;
        }
    }

}
