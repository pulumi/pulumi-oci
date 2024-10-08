// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.GloballyDistributedDatabase.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetShardedDatabasePatchOperation {
    private String operation;
    private String selection;
    private String value;

    private GetShardedDatabasePatchOperation() {}
    public String operation() {
        return this.operation;
    }
    public String selection() {
        return this.selection;
    }
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetShardedDatabasePatchOperation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String operation;
        private String selection;
        private String value;
        public Builder() {}
        public Builder(GetShardedDatabasePatchOperation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.operation = defaults.operation;
    	      this.selection = defaults.selection;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder operation(String operation) {
            if (operation == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabasePatchOperation", "operation");
            }
            this.operation = operation;
            return this;
        }
        @CustomType.Setter
        public Builder selection(String selection) {
            if (selection == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabasePatchOperation", "selection");
            }
            this.selection = selection;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetShardedDatabasePatchOperation", "value");
            }
            this.value = value;
            return this;
        }
        public GetShardedDatabasePatchOperation build() {
            final var _resultValue = new GetShardedDatabasePatchOperation();
            _resultValue.operation = operation;
            _resultValue.selection = selection;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
