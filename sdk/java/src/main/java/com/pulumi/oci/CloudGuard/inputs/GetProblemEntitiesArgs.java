// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.CloudGuard.inputs.GetProblemEntitiesFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetProblemEntitiesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetProblemEntitiesArgs Empty = new GetProblemEntitiesArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetProblemEntitiesFilterArgs>> filters;

    public Optional<Output<List<GetProblemEntitiesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * OCID of the problem.
     * 
     */
    @Import(name="problemId", required=true)
    private Output<String> problemId;

    /**
     * @return OCID of the problem.
     * 
     */
    public Output<String> problemId() {
        return this.problemId;
    }

    private GetProblemEntitiesArgs() {}

    private GetProblemEntitiesArgs(GetProblemEntitiesArgs $) {
        this.filters = $.filters;
        this.problemId = $.problemId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetProblemEntitiesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetProblemEntitiesArgs $;

        public Builder() {
            $ = new GetProblemEntitiesArgs();
        }

        public Builder(GetProblemEntitiesArgs defaults) {
            $ = new GetProblemEntitiesArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetProblemEntitiesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetProblemEntitiesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetProblemEntitiesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param problemId OCID of the problem.
         * 
         * @return builder
         * 
         */
        public Builder problemId(Output<String> problemId) {
            $.problemId = problemId;
            return this;
        }

        /**
         * @param problemId OCID of the problem.
         * 
         * @return builder
         * 
         */
        public Builder problemId(String problemId) {
            return problemId(Output.of(problemId));
        }

        public GetProblemEntitiesArgs build() {
            if ($.problemId == null) {
                throw new MissingRequiredPropertyException("GetProblemEntitiesArgs", "problemId");
            }
            return $;
        }
    }

}
