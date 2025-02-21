// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetProblemEntityArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetProblemEntityArgs Empty = new GetProblemEntityArgs();

    /**
     * OCId of the problem.
     * 
     */
    @Import(name="problemId", required=true)
    private Output<String> problemId;

    /**
     * @return OCId of the problem.
     * 
     */
    public Output<String> problemId() {
        return this.problemId;
    }

    private GetProblemEntityArgs() {}

    private GetProblemEntityArgs(GetProblemEntityArgs $) {
        this.problemId = $.problemId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetProblemEntityArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetProblemEntityArgs $;

        public Builder() {
            $ = new GetProblemEntityArgs();
        }

        public Builder(GetProblemEntityArgs defaults) {
            $ = new GetProblemEntityArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param problemId OCId of the problem.
         * 
         * @return builder
         * 
         */
        public Builder problemId(Output<String> problemId) {
            $.problemId = problemId;
            return this;
        }

        /**
         * @param problemId OCId of the problem.
         * 
         * @return builder
         * 
         */
        public Builder problemId(String problemId) {
            return problemId(Output.of(problemId));
        }

        public GetProblemEntityArgs build() {
            if ($.problemId == null) {
                throw new MissingRequiredPropertyException("GetProblemEntityArgs", "problemId");
            }
            return $;
        }
    }

}
