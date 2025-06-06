// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.BigDataService.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class BdsInstanceSoftwareUpdateActionState extends com.pulumi.resources.ResourceArgs {

    public static final BdsInstanceSoftwareUpdateActionState Empty = new BdsInstanceSoftwareUpdateActionState();

    /**
     * The OCID of the cluster.
     * 
     */
    @Import(name="bdsInstanceId")
    private @Nullable Output<String> bdsInstanceId;

    /**
     * @return The OCID of the cluster.
     * 
     */
    public Optional<Output<String>> bdsInstanceId() {
        return Optional.ofNullable(this.bdsInstanceId);
    }

    @Import(name="softwareUpdateKeys")
    private @Nullable Output<List<String>> softwareUpdateKeys;

    public Optional<Output<List<String>>> softwareUpdateKeys() {
        return Optional.ofNullable(this.softwareUpdateKeys);
    }

    private BdsInstanceSoftwareUpdateActionState() {}

    private BdsInstanceSoftwareUpdateActionState(BdsInstanceSoftwareUpdateActionState $) {
        this.bdsInstanceId = $.bdsInstanceId;
        this.softwareUpdateKeys = $.softwareUpdateKeys;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(BdsInstanceSoftwareUpdateActionState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private BdsInstanceSoftwareUpdateActionState $;

        public Builder() {
            $ = new BdsInstanceSoftwareUpdateActionState();
        }

        public Builder(BdsInstanceSoftwareUpdateActionState defaults) {
            $ = new BdsInstanceSoftwareUpdateActionState(Objects.requireNonNull(defaults));
        }

        /**
         * @param bdsInstanceId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder bdsInstanceId(@Nullable Output<String> bdsInstanceId) {
            $.bdsInstanceId = bdsInstanceId;
            return this;
        }

        /**
         * @param bdsInstanceId The OCID of the cluster.
         * 
         * @return builder
         * 
         */
        public Builder bdsInstanceId(String bdsInstanceId) {
            return bdsInstanceId(Output.of(bdsInstanceId));
        }

        public Builder softwareUpdateKeys(@Nullable Output<List<String>> softwareUpdateKeys) {
            $.softwareUpdateKeys = softwareUpdateKeys;
            return this;
        }

        public Builder softwareUpdateKeys(List<String> softwareUpdateKeys) {
            return softwareUpdateKeys(Output.of(softwareUpdateKeys));
        }

        public Builder softwareUpdateKeys(String... softwareUpdateKeys) {
            return softwareUpdateKeys(List.of(softwareUpdateKeys));
        }

        public BdsInstanceSoftwareUpdateActionState build() {
            return $;
        }
    }

}
