// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class ExadataInfrastructureStorageMaintenanceWindowDaysOfWeekArgs extends com.pulumi.resources.ResourceArgs {

    public static final ExadataInfrastructureStorageMaintenanceWindowDaysOfWeekArgs Empty = new ExadataInfrastructureStorageMaintenanceWindowDaysOfWeekArgs();

    @Import(name="name", required=true)
    private Output<String> name;

    public Output<String> name() {
        return this.name;
    }

    private ExadataInfrastructureStorageMaintenanceWindowDaysOfWeekArgs() {}

    private ExadataInfrastructureStorageMaintenanceWindowDaysOfWeekArgs(ExadataInfrastructureStorageMaintenanceWindowDaysOfWeekArgs $) {
        this.name = $.name;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ExadataInfrastructureStorageMaintenanceWindowDaysOfWeekArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ExadataInfrastructureStorageMaintenanceWindowDaysOfWeekArgs $;

        public Builder() {
            $ = new ExadataInfrastructureStorageMaintenanceWindowDaysOfWeekArgs();
        }

        public Builder(ExadataInfrastructureStorageMaintenanceWindowDaysOfWeekArgs defaults) {
            $ = new ExadataInfrastructureStorageMaintenanceWindowDaysOfWeekArgs(Objects.requireNonNull(defaults));
        }

        public Builder name(Output<String> name) {
            $.name = name;
            return this;
        }

        public Builder name(String name) {
            return name(Output.of(name));
        }

        public ExadataInfrastructureStorageMaintenanceWindowDaysOfWeekArgs build() {
            $.name = Objects.requireNonNull($.name, "expected parameter 'name' to be non-null");
            return $;
        }
    }

}