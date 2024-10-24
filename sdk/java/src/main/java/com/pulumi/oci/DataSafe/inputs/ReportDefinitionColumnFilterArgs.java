// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;


public final class ReportDefinitionColumnFilterArgs extends com.pulumi.resources.ResourceArgs {

    public static final ReportDefinitionColumnFilterArgs Empty = new ReportDefinitionColumnFilterArgs();

    /**
     * (Updatable) An array of expressions based on the operator type. A filter may have one or more expressions.
     * 
     */
    @Import(name="expressions", required=true)
    private Output<List<String>> expressions;

    /**
     * @return (Updatable) An array of expressions based on the operator type. A filter may have one or more expressions.
     * 
     */
    public Output<List<String>> expressions() {
        return this.expressions;
    }

    /**
     * (Updatable) Name of the column on which the filter must be applied.
     * 
     */
    @Import(name="fieldName", required=true)
    private Output<String> fieldName;

    /**
     * @return (Updatable) Name of the column on which the filter must be applied.
     * 
     */
    public Output<String> fieldName() {
        return this.fieldName;
    }

    /**
     * (Updatable) Indicates whether the filter is enabled. Values can either be &#39;true&#39; or &#39;false&#39;.
     * 
     */
    @Import(name="isEnabled", required=true)
    private Output<Boolean> isEnabled;

    /**
     * @return (Updatable) Indicates whether the filter is enabled. Values can either be &#39;true&#39; or &#39;false&#39;.
     * 
     */
    public Output<Boolean> isEnabled() {
        return this.isEnabled;
    }

    /**
     * (Updatable) Indicates whether the filter is hidden. Values can either be &#39;true&#39; or &#39;false&#39;.
     * 
     */
    @Import(name="isHidden", required=true)
    private Output<Boolean> isHidden;

    /**
     * @return (Updatable) Indicates whether the filter is hidden. Values can either be &#39;true&#39; or &#39;false&#39;.
     * 
     */
    public Output<Boolean> isHidden() {
        return this.isHidden;
    }

    /**
     * (Updatable) Specifies the type of operator that must be applied for example in, eq etc.
     * 
     */
    @Import(name="operator", required=true)
    private Output<String> operator;

    /**
     * @return (Updatable) Specifies the type of operator that must be applied for example in, eq etc.
     * 
     */
    public Output<String> operator() {
        return this.operator;
    }

    private ReportDefinitionColumnFilterArgs() {}

    private ReportDefinitionColumnFilterArgs(ReportDefinitionColumnFilterArgs $) {
        this.expressions = $.expressions;
        this.fieldName = $.fieldName;
        this.isEnabled = $.isEnabled;
        this.isHidden = $.isHidden;
        this.operator = $.operator;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(ReportDefinitionColumnFilterArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private ReportDefinitionColumnFilterArgs $;

        public Builder() {
            $ = new ReportDefinitionColumnFilterArgs();
        }

        public Builder(ReportDefinitionColumnFilterArgs defaults) {
            $ = new ReportDefinitionColumnFilterArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param expressions (Updatable) An array of expressions based on the operator type. A filter may have one or more expressions.
         * 
         * @return builder
         * 
         */
        public Builder expressions(Output<List<String>> expressions) {
            $.expressions = expressions;
            return this;
        }

        /**
         * @param expressions (Updatable) An array of expressions based on the operator type. A filter may have one or more expressions.
         * 
         * @return builder
         * 
         */
        public Builder expressions(List<String> expressions) {
            return expressions(Output.of(expressions));
        }

        /**
         * @param expressions (Updatable) An array of expressions based on the operator type. A filter may have one or more expressions.
         * 
         * @return builder
         * 
         */
        public Builder expressions(String... expressions) {
            return expressions(List.of(expressions));
        }

        /**
         * @param fieldName (Updatable) Name of the column on which the filter must be applied.
         * 
         * @return builder
         * 
         */
        public Builder fieldName(Output<String> fieldName) {
            $.fieldName = fieldName;
            return this;
        }

        /**
         * @param fieldName (Updatable) Name of the column on which the filter must be applied.
         * 
         * @return builder
         * 
         */
        public Builder fieldName(String fieldName) {
            return fieldName(Output.of(fieldName));
        }

        /**
         * @param isEnabled (Updatable) Indicates whether the filter is enabled. Values can either be &#39;true&#39; or &#39;false&#39;.
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(Output<Boolean> isEnabled) {
            $.isEnabled = isEnabled;
            return this;
        }

        /**
         * @param isEnabled (Updatable) Indicates whether the filter is enabled. Values can either be &#39;true&#39; or &#39;false&#39;.
         * 
         * @return builder
         * 
         */
        public Builder isEnabled(Boolean isEnabled) {
            return isEnabled(Output.of(isEnabled));
        }

        /**
         * @param isHidden (Updatable) Indicates whether the filter is hidden. Values can either be &#39;true&#39; or &#39;false&#39;.
         * 
         * @return builder
         * 
         */
        public Builder isHidden(Output<Boolean> isHidden) {
            $.isHidden = isHidden;
            return this;
        }

        /**
         * @param isHidden (Updatable) Indicates whether the filter is hidden. Values can either be &#39;true&#39; or &#39;false&#39;.
         * 
         * @return builder
         * 
         */
        public Builder isHidden(Boolean isHidden) {
            return isHidden(Output.of(isHidden));
        }

        /**
         * @param operator (Updatable) Specifies the type of operator that must be applied for example in, eq etc.
         * 
         * @return builder
         * 
         */
        public Builder operator(Output<String> operator) {
            $.operator = operator;
            return this;
        }

        /**
         * @param operator (Updatable) Specifies the type of operator that must be applied for example in, eq etc.
         * 
         * @return builder
         * 
         */
        public Builder operator(String operator) {
            return operator(Output.of(operator));
        }

        public ReportDefinitionColumnFilterArgs build() {
            if ($.expressions == null) {
                throw new MissingRequiredPropertyException("ReportDefinitionColumnFilterArgs", "expressions");
            }
            if ($.fieldName == null) {
                throw new MissingRequiredPropertyException("ReportDefinitionColumnFilterArgs", "fieldName");
            }
            if ($.isEnabled == null) {
                throw new MissingRequiredPropertyException("ReportDefinitionColumnFilterArgs", "isEnabled");
            }
            if ($.isHidden == null) {
                throw new MissingRequiredPropertyException("ReportDefinitionColumnFilterArgs", "isHidden");
            }
            if ($.operator == null) {
                throw new MissingRequiredPropertyException("ReportDefinitionColumnFilterArgs", "operator");
            }
            return $;
        }
    }

}
