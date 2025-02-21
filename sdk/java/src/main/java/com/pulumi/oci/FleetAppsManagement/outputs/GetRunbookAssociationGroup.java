// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetRunbookAssociationGroupProperty;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRunbookAssociationGroup {
    /**
     * @return The name of the task
     * 
     */
    private String name;
    /**
     * @return The properties of the task.
     * 
     */
    private List<GetRunbookAssociationGroupProperty> properties;
    /**
     * @return The type of the runbook.
     * 
     */
    private String type;

    private GetRunbookAssociationGroup() {}
    /**
     * @return The name of the task
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The properties of the task.
     * 
     */
    public List<GetRunbookAssociationGroupProperty> properties() {
        return this.properties;
    }
    /**
     * @return The type of the runbook.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRunbookAssociationGroup defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String name;
        private List<GetRunbookAssociationGroupProperty> properties;
        private String type;
        public Builder() {}
        public Builder(GetRunbookAssociationGroup defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.properties = defaults.properties;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetRunbookAssociationGroup", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder properties(List<GetRunbookAssociationGroupProperty> properties) {
            if (properties == null) {
              throw new MissingRequiredPropertyException("GetRunbookAssociationGroup", "properties");
            }
            this.properties = properties;
            return this;
        }
        public Builder properties(GetRunbookAssociationGroupProperty... properties) {
            return properties(List.of(properties));
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("GetRunbookAssociationGroup", "type");
            }
            this.type = type;
            return this;
        }
        public GetRunbookAssociationGroup build() {
            final var _resultValue = new GetRunbookAssociationGroup();
            _resultValue.name = name;
            _resultValue.properties = properties;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
