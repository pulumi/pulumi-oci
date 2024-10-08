// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Jms.outputs.GetFleetBlocklistsItemTarget;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetFleetBlocklistsItem {
    /**
     * @return The unique identifier of this blocklist record.
     * 
     */
    private String key;
    /**
     * @return The operation type.
     * 
     */
    private String operation;
    /**
     * @return The reason why the operation is blocklisted.
     * 
     */
    private String reason;
    /**
     * @return A resource to blocklist for certain operation.
     * 
     */
    private List<GetFleetBlocklistsItemTarget> targets;

    private GetFleetBlocklistsItem() {}
    /**
     * @return The unique identifier of this blocklist record.
     * 
     */
    public String key() {
        return this.key;
    }
    /**
     * @return The operation type.
     * 
     */
    public String operation() {
        return this.operation;
    }
    /**
     * @return The reason why the operation is blocklisted.
     * 
     */
    public String reason() {
        return this.reason;
    }
    /**
     * @return A resource to blocklist for certain operation.
     * 
     */
    public List<GetFleetBlocklistsItemTarget> targets() {
        return this.targets;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFleetBlocklistsItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String key;
        private String operation;
        private String reason;
        private List<GetFleetBlocklistsItemTarget> targets;
        public Builder() {}
        public Builder(GetFleetBlocklistsItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.key = defaults.key;
    	      this.operation = defaults.operation;
    	      this.reason = defaults.reason;
    	      this.targets = defaults.targets;
        }

        @CustomType.Setter
        public Builder key(String key) {
            if (key == null) {
              throw new MissingRequiredPropertyException("GetFleetBlocklistsItem", "key");
            }
            this.key = key;
            return this;
        }
        @CustomType.Setter
        public Builder operation(String operation) {
            if (operation == null) {
              throw new MissingRequiredPropertyException("GetFleetBlocklistsItem", "operation");
            }
            this.operation = operation;
            return this;
        }
        @CustomType.Setter
        public Builder reason(String reason) {
            if (reason == null) {
              throw new MissingRequiredPropertyException("GetFleetBlocklistsItem", "reason");
            }
            this.reason = reason;
            return this;
        }
        @CustomType.Setter
        public Builder targets(List<GetFleetBlocklistsItemTarget> targets) {
            if (targets == null) {
              throw new MissingRequiredPropertyException("GetFleetBlocklistsItem", "targets");
            }
            this.targets = targets;
            return this;
        }
        public Builder targets(GetFleetBlocklistsItemTarget... targets) {
            return targets(List.of(targets));
        }
        public GetFleetBlocklistsItem build() {
            final var _resultValue = new GetFleetBlocklistsItem();
            _resultValue.key = key;
            _resultValue.operation = operation;
            _resultValue.reason = reason;
            _resultValue.targets = targets;
            return _resultValue;
        }
    }
}
