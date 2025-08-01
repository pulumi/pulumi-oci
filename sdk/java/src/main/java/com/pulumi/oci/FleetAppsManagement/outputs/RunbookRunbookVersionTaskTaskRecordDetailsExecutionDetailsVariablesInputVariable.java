// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class RunbookRunbookVersionTaskTaskRecordDetailsExecutionDetailsVariablesInputVariable {
    /**
     * @return The description of the argument.
     * 
     */
    private @Nullable String description;
    /**
     * @return The name of the argument.
     * 
     */
    private @Nullable String name;
    /**
     * @return Input argument Type.
     * 
     */
    private @Nullable String type;

    private RunbookRunbookVersionTaskTaskRecordDetailsExecutionDetailsVariablesInputVariable() {}
    /**
     * @return The description of the argument.
     * 
     */
    public Optional<String> description() {
        return Optional.ofNullable(this.description);
    }
    /**
     * @return The name of the argument.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return Input argument Type.
     * 
     */
    public Optional<String> type() {
        return Optional.ofNullable(this.type);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(RunbookRunbookVersionTaskTaskRecordDetailsExecutionDetailsVariablesInputVariable defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String description;
        private @Nullable String name;
        private @Nullable String type;
        public Builder() {}
        public Builder(RunbookRunbookVersionTaskTaskRecordDetailsExecutionDetailsVariablesInputVariable defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.description = defaults.description;
    	      this.name = defaults.name;
    	      this.type = defaults.type;
        }

        @CustomType.Setter
        public Builder description(@Nullable String description) {

            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {

            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder type(@Nullable String type) {

            this.type = type;
            return this;
        }
        public RunbookRunbookVersionTaskTaskRecordDetailsExecutionDetailsVariablesInputVariable build() {
            final var _resultValue = new RunbookRunbookVersionTaskTaskRecordDetailsExecutionDetailsVariablesInputVariable();
            _resultValue.description = description;
            _resultValue.name = name;
            _resultValue.type = type;
            return _resultValue;
        }
    }
}
