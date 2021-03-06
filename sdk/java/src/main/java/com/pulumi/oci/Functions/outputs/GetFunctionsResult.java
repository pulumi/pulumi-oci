// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Functions.outputs.GetFunctionsFilter;
import com.pulumi.oci.Functions.outputs.GetFunctionsFunction;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetFunctionsResult {
    /**
     * @return The OCID of the application the function belongs to.
     * 
     */
    private final String applicationId;
    /**
     * @return The display name of the function. The display name is unique within the application containing the function.
     * 
     */
    private final @Nullable String displayName;
    private final @Nullable List<GetFunctionsFilter> filters;
    /**
     * @return The list of functions.
     * 
     */
    private final List<GetFunctionsFunction> functions;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the function.
     * 
     */
    private final @Nullable String id;
    /**
     * @return The current state of the function.
     * 
     */
    private final @Nullable String state;

    @CustomType.Constructor
    private GetFunctionsResult(
        @CustomType.Parameter("applicationId") String applicationId,
        @CustomType.Parameter("displayName") @Nullable String displayName,
        @CustomType.Parameter("filters") @Nullable List<GetFunctionsFilter> filters,
        @CustomType.Parameter("functions") List<GetFunctionsFunction> functions,
        @CustomType.Parameter("id") @Nullable String id,
        @CustomType.Parameter("state") @Nullable String state) {
        this.applicationId = applicationId;
        this.displayName = displayName;
        this.filters = filters;
        this.functions = functions;
        this.id = id;
        this.state = state;
    }

    /**
     * @return The OCID of the application the function belongs to.
     * 
     */
    public String applicationId() {
        return this.applicationId;
    }
    /**
     * @return The display name of the function. The display name is unique within the application containing the function.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetFunctionsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The list of functions.
     * 
     */
    public List<GetFunctionsFunction> functions() {
        return this.functions;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the function.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The current state of the function.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFunctionsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String applicationId;
        private @Nullable String displayName;
        private @Nullable List<GetFunctionsFilter> filters;
        private List<GetFunctionsFunction> functions;
        private @Nullable String id;
        private @Nullable String state;

        public Builder() {
    	      // Empty
        }

        public Builder(GetFunctionsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicationId = defaults.applicationId;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.functions = defaults.functions;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
        }

        public Builder applicationId(String applicationId) {
            this.applicationId = Objects.requireNonNull(applicationId);
            return this;
        }
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        public Builder filters(@Nullable List<GetFunctionsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetFunctionsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder functions(List<GetFunctionsFunction> functions) {
            this.functions = Objects.requireNonNull(functions);
            return this;
        }
        public Builder functions(GetFunctionsFunction... functions) {
            return functions(List.of(functions));
        }
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }        public GetFunctionsResult build() {
            return new GetFunctionsResult(applicationId, displayName, filters, functions, id, state);
        }
    }
}
