// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class SoftwareSourceChangeAvailabilityManagementSoftwareSourceAvailability {
    /**
     * @return Availability of the software source to instances in private data centers or third-party clouds.
     * 
     */
    private @Nullable String availability;
    /**
     * @return Availability of the software source to Oracle Cloud Infrastructure instances.
     * 
     */
    private @Nullable String availabilityAtOci;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the vendor software source.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    private String softwareSourceId;

    private SoftwareSourceChangeAvailabilityManagementSoftwareSourceAvailability() {}
    /**
     * @return Availability of the software source to instances in private data centers or third-party clouds.
     * 
     */
    public Optional<String> availability() {
        return Optional.ofNullable(this.availability);
    }
    /**
     * @return Availability of the software source to Oracle Cloud Infrastructure instances.
     * 
     */
    public Optional<String> availabilityAtOci() {
        return Optional.ofNullable(this.availabilityAtOci);
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the vendor software source.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public String softwareSourceId() {
        return this.softwareSourceId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(SoftwareSourceChangeAvailabilityManagementSoftwareSourceAvailability defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String availability;
        private @Nullable String availabilityAtOci;
        private String softwareSourceId;
        public Builder() {}
        public Builder(SoftwareSourceChangeAvailabilityManagementSoftwareSourceAvailability defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availability = defaults.availability;
    	      this.availabilityAtOci = defaults.availabilityAtOci;
    	      this.softwareSourceId = defaults.softwareSourceId;
        }

        @CustomType.Setter
        public Builder availability(@Nullable String availability) {

            this.availability = availability;
            return this;
        }
        @CustomType.Setter
        public Builder availabilityAtOci(@Nullable String availabilityAtOci) {

            this.availabilityAtOci = availabilityAtOci;
            return this;
        }
        @CustomType.Setter
        public Builder softwareSourceId(String softwareSourceId) {
            if (softwareSourceId == null) {
              throw new MissingRequiredPropertyException("SoftwareSourceChangeAvailabilityManagementSoftwareSourceAvailability", "softwareSourceId");
            }
            this.softwareSourceId = softwareSourceId;
            return this;
        }
        public SoftwareSourceChangeAvailabilityManagementSoftwareSourceAvailability build() {
            final var _resultValue = new SoftwareSourceChangeAvailabilityManagementSoftwareSourceAvailability();
            _resultValue.availability = availability;
            _resultValue.availabilityAtOci = availabilityAtOci;
            _resultValue.softwareSourceId = softwareSourceId;
            return _resultValue;
        }
    }
}
