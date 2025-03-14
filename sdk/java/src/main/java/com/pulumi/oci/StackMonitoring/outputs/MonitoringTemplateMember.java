// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MonitoringTemplateMember {
    /**
     * @return (Updatable) The OCID of the composite resource type like EBS or Peoplesoft.
     * 
     */
    private @Nullable String compositeType;
    /**
     * @return (Updatable) The OCID of the resourceInstance/resourceType/resourceGroup
     * 
     */
    private String id;
    /**
     * @return (Updatable) Type of the member reference RESOURCE_INSTANCE, RESOURCE_TYPE, RESOURCE_GROUP
     * 
     */
    private String type;

    private MonitoringTemplateMember() {}
    /**
     * @return (Updatable) The OCID of the composite resource type like EBS or Peoplesoft.
     * 
     */
    public Optional<String> compositeType() {
        return Optional.ofNullable(this.compositeType);
    }
    /**
     * @return (Updatable) The OCID of the resourceInstance/resourceType/resourceGroup
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return (Updatable) Type of the member reference RESOURCE_INSTANCE, RESOURCE_TYPE, RESOURCE_GROUP
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MonitoringTemplateMember defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compositeType;
        private String id;
        private String type;
        public Builder() {}
        public Builder(MonitoringTemplateMember defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compositeType = defaults.compositeType;
    	      this.id = defaults.id;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder compositeType(@Nullable String compositeType) {

            this.compositeType = compositeType;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("MonitoringTemplateMember", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("MonitoringTemplateMember", "type");
            }
            this.type = type;
            return this;
        }
        public MonitoringTemplateMember build() {
            final var _resultValue = new MonitoringTemplateMember();
            _resultValue.compositeType = compositeType;
            _resultValue.id = id;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
