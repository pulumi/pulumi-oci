// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class PluggableDatabasePluggableDatabaseManagementConfigArgs extends com.pulumi.resources.ResourceArgs {

    public static final PluggableDatabasePluggableDatabaseManagementConfigArgs Empty = new PluggableDatabasePluggableDatabaseManagementConfigArgs();

    /**
     * The status of the Pluggable Database Management service.
     * 
     */
    @Import(name="managementStatus")
    private @Nullable Output<String> managementStatus;

    /**
     * @return The status of the Pluggable Database Management service.
     * 
     */
    public Optional<Output<String>> managementStatus() {
        return Optional.ofNullable(this.managementStatus);
    }

    private PluggableDatabasePluggableDatabaseManagementConfigArgs() {}

    private PluggableDatabasePluggableDatabaseManagementConfigArgs(PluggableDatabasePluggableDatabaseManagementConfigArgs $) {
        this.managementStatus = $.managementStatus;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(PluggableDatabasePluggableDatabaseManagementConfigArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private PluggableDatabasePluggableDatabaseManagementConfigArgs $;

        public Builder() {
            $ = new PluggableDatabasePluggableDatabaseManagementConfigArgs();
        }

        public Builder(PluggableDatabasePluggableDatabaseManagementConfigArgs defaults) {
            $ = new PluggableDatabasePluggableDatabaseManagementConfigArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param managementStatus The status of the Pluggable Database Management service.
         * 
         * @return builder
         * 
         */
        public Builder managementStatus(@Nullable Output<String> managementStatus) {
            $.managementStatus = managementStatus;
            return this;
        }

        /**
         * @param managementStatus The status of the Pluggable Database Management service.
         * 
         * @return builder
         * 
         */
        public Builder managementStatus(String managementStatus) {
            return managementStatus(Output.of(managementStatus));
        }

        public PluggableDatabasePluggableDatabaseManagementConfigArgs build() {
            return $;
        }
    }

}