// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Double;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class LibraryMasingFormatFormatEntry {
    /**
     * @return (Updatable) The name of the substitution column.
     * 
     */
    private @Nullable String columnName;
    /**
     * @return (Updatable) The description of the format entry.
     * 
     */
    private @Nullable String description;
    /**
     * @return (Updatable) The upper bound of the range within which all the original column values fall. The end date must be greater than or equal to the start date.
     * 
     */
    private @Nullable String endDate;
    /**
     * @return (Updatable) The maximum number of characters the generated strings should have. It can  be any integer greater than zero, but it must be greater than or equal to  the start length.
     * 
     */
    private @Nullable Integer endLength;
    /**
     * @return (Updatable) The upper bound of the range within which random decimal numbers should be generated. It must be greater than or equal to the start value. It supports  input of double type.
     * 
     */
    private @Nullable Double endValue;
    /**
     * @return (Updatable) The constant number to be used for masking.
     * 
     */
    private @Nullable Double fixedNumber;
    /**
     * @return (Updatable) The constant string to be used for masking.
     * 
     */
    private @Nullable String fixedString;
    /**
     * @return (Updatable) One or more reference columns to be used to group column values so that they can be shuffled within their own group. The grouping columns and  the column to be masked must belong to the same table.
     * 
     */
    private @Nullable List<String> groupingColumns;
    /**
     * @return (Updatable) The number of characters that should be there in the substring. It should be an integer and greater than zero.
     * 
     */
    private @Nullable Integer length;
    /**
     * @return (Updatable) The OCID of the library masking format.
     * 
     */
    private @Nullable String libraryMaskingFormatId;
    /**
     * @return (Updatable) The pattern that should be used to mask data.
     * 
     */
    private @Nullable String pattern;
    /**
     * @return (Updatable) The post processing function in SCHEMA_NAME.PACKAGE_NAME.FUNCTION_NAME format. It can be a standalone or packaged function, so PACKAGE_NAME is optional.
     * 
     */
    private @Nullable String postProcessingFunction;
    /**
     * @return (Updatable) A comma-separated list of values to be used to replace column values. The list can be of strings, numbers, or dates. The data type of each value in the list must be compatible with the data type of the column. The number of entries in the list cannot be more than 999.
     * 
     */
    private @Nullable List<String> randomLists;
    /**
     * @return (Updatable) The regular expression to be used for masking. For data with characters in the ASCII character set, providing a regular expression is optional. However, it  is required if the data contains multi-byte characters. If not provided, an  error is returned when a multi-byte character is found.
     * 
     * In the case of ASCII characters, if a regular expression is not provided,  Deterministic Encryption can encrypt variable-length column values while  preserving their original format.
     * 
     * If a regular expression is provided, the column values in all the rows must match  the regular expression. Deterministic Encryption supports a subset of the regular  expression language. It supports encryption of fixed-length strings, and does not  support * or + syntax of regular expressions. The encrypted values also match the  regular expression, which helps to ensure that the original format is preserved.  If an original value does not match the regular expression, Deterministic Encryption  might not produce a one-to-one mapping. All non-confirming values are mapped to a  single encrypted value, thereby producing a many-to-one mapping.
     * 
     */
    private @Nullable String regularExpression;
    /**
     * @return (Updatable) The value that should be used to replace the data matching the regular  expression. It can be a fixed string, fixed number or null value.
     * 
     */
    private @Nullable String replaceWith;
    /**
     * @return (Updatable) The name of the schema that contains the substitution column.
     * 
     */
    private @Nullable String schemaName;
    /**
     * @return (Updatable) The SQL expression to be used to generate the masked values. It can  consist of one or more values, operators, and SQL functions that  evaluate to a value. It can also contain substitution columns from  the same table. Specify the substitution columns within percent (%)  symbols.
     * 
     */
    private @Nullable String sqlExpression;
    /**
     * @return (Updatable) The lower bound of the range within which all the original column values fall. The start date must be less than or equal to the end date.
     * 
     */
    private @Nullable String startDate;
    /**
     * @return (Updatable) The minimum number of characters the generated strings should have. It can  be any integer greater than zero, but it must be less than or equal to the  end length.
     * 
     */
    private @Nullable Integer startLength;
    /**
     * @return (Updatable) The starting position in the original string from where the substring should be extracted. It can be either a positive or a negative integer. If It&#39;s negative, the counting starts from the end of the string.
     * 
     */
    private @Nullable Integer startPosition;
    /**
     * @return (Updatable) The lower bound of the range within which random decimal numbers should  be generated. It must be less than or equal to the end value. It supports  input of double type.
     * 
     */
    private @Nullable Double startValue;
    /**
     * @return (Updatable) The name of the table that contains the substitution column.
     * 
     */
    private @Nullable String tableName;
    /**
     * @return (Updatable) The type of the format entry.
     * 
     */
    private String type;
    /**
     * @return (Updatable) The user-defined function in SCHEMA_NAME.PACKAGE_NAME.FUNCTION_NAME format.  It can be a standalone or packaged function, so PACKAGE_NAME is optional.
     * 
     */
    private @Nullable String userDefinedFunction;

    private LibraryMasingFormatFormatEntry() {}
    /**
     * @return (Updatable) The name of the substitution column.
     * 
     */
    public Optional<String> columnName() {
        return Optional.ofNullable(this.columnName);
    }
    /**
     * @return (Updatable) The description of the format entry.
     * 
     */
    public Optional<String> description() {
        return Optional.ofNullable(this.description);
    }
    /**
     * @return (Updatable) The upper bound of the range within which all the original column values fall. The end date must be greater than or equal to the start date.
     * 
     */
    public Optional<String> endDate() {
        return Optional.ofNullable(this.endDate);
    }
    /**
     * @return (Updatable) The maximum number of characters the generated strings should have. It can  be any integer greater than zero, but it must be greater than or equal to  the start length.
     * 
     */
    public Optional<Integer> endLength() {
        return Optional.ofNullable(this.endLength);
    }
    /**
     * @return (Updatable) The upper bound of the range within which random decimal numbers should be generated. It must be greater than or equal to the start value. It supports  input of double type.
     * 
     */
    public Optional<Double> endValue() {
        return Optional.ofNullable(this.endValue);
    }
    /**
     * @return (Updatable) The constant number to be used for masking.
     * 
     */
    public Optional<Double> fixedNumber() {
        return Optional.ofNullable(this.fixedNumber);
    }
    /**
     * @return (Updatable) The constant string to be used for masking.
     * 
     */
    public Optional<String> fixedString() {
        return Optional.ofNullable(this.fixedString);
    }
    /**
     * @return (Updatable) One or more reference columns to be used to group column values so that they can be shuffled within their own group. The grouping columns and  the column to be masked must belong to the same table.
     * 
     */
    public List<String> groupingColumns() {
        return this.groupingColumns == null ? List.of() : this.groupingColumns;
    }
    /**
     * @return (Updatable) The number of characters that should be there in the substring. It should be an integer and greater than zero.
     * 
     */
    public Optional<Integer> length() {
        return Optional.ofNullable(this.length);
    }
    /**
     * @return (Updatable) The OCID of the library masking format.
     * 
     */
    public Optional<String> libraryMaskingFormatId() {
        return Optional.ofNullable(this.libraryMaskingFormatId);
    }
    /**
     * @return (Updatable) The pattern that should be used to mask data.
     * 
     */
    public Optional<String> pattern() {
        return Optional.ofNullable(this.pattern);
    }
    /**
     * @return (Updatable) The post processing function in SCHEMA_NAME.PACKAGE_NAME.FUNCTION_NAME format. It can be a standalone or packaged function, so PACKAGE_NAME is optional.
     * 
     */
    public Optional<String> postProcessingFunction() {
        return Optional.ofNullable(this.postProcessingFunction);
    }
    /**
     * @return (Updatable) A comma-separated list of values to be used to replace column values. The list can be of strings, numbers, or dates. The data type of each value in the list must be compatible with the data type of the column. The number of entries in the list cannot be more than 999.
     * 
     */
    public List<String> randomLists() {
        return this.randomLists == null ? List.of() : this.randomLists;
    }
    /**
     * @return (Updatable) The regular expression to be used for masking. For data with characters in the ASCII character set, providing a regular expression is optional. However, it  is required if the data contains multi-byte characters. If not provided, an  error is returned when a multi-byte character is found.
     * 
     * In the case of ASCII characters, if a regular expression is not provided,  Deterministic Encryption can encrypt variable-length column values while  preserving their original format.
     * 
     * If a regular expression is provided, the column values in all the rows must match  the regular expression. Deterministic Encryption supports a subset of the regular  expression language. It supports encryption of fixed-length strings, and does not  support * or + syntax of regular expressions. The encrypted values also match the  regular expression, which helps to ensure that the original format is preserved.  If an original value does not match the regular expression, Deterministic Encryption  might not produce a one-to-one mapping. All non-confirming values are mapped to a  single encrypted value, thereby producing a many-to-one mapping.
     * 
     */
    public Optional<String> regularExpression() {
        return Optional.ofNullable(this.regularExpression);
    }
    /**
     * @return (Updatable) The value that should be used to replace the data matching the regular  expression. It can be a fixed string, fixed number or null value.
     * 
     */
    public Optional<String> replaceWith() {
        return Optional.ofNullable(this.replaceWith);
    }
    /**
     * @return (Updatable) The name of the schema that contains the substitution column.
     * 
     */
    public Optional<String> schemaName() {
        return Optional.ofNullable(this.schemaName);
    }
    /**
     * @return (Updatable) The SQL expression to be used to generate the masked values. It can  consist of one or more values, operators, and SQL functions that  evaluate to a value. It can also contain substitution columns from  the same table. Specify the substitution columns within percent (%)  symbols.
     * 
     */
    public Optional<String> sqlExpression() {
        return Optional.ofNullable(this.sqlExpression);
    }
    /**
     * @return (Updatable) The lower bound of the range within which all the original column values fall. The start date must be less than or equal to the end date.
     * 
     */
    public Optional<String> startDate() {
        return Optional.ofNullable(this.startDate);
    }
    /**
     * @return (Updatable) The minimum number of characters the generated strings should have. It can  be any integer greater than zero, but it must be less than or equal to the  end length.
     * 
     */
    public Optional<Integer> startLength() {
        return Optional.ofNullable(this.startLength);
    }
    /**
     * @return (Updatable) The starting position in the original string from where the substring should be extracted. It can be either a positive or a negative integer. If It&#39;s negative, the counting starts from the end of the string.
     * 
     */
    public Optional<Integer> startPosition() {
        return Optional.ofNullable(this.startPosition);
    }
    /**
     * @return (Updatable) The lower bound of the range within which random decimal numbers should  be generated. It must be less than or equal to the end value. It supports  input of double type.
     * 
     */
    public Optional<Double> startValue() {
        return Optional.ofNullable(this.startValue);
    }
    /**
     * @return (Updatable) The name of the table that contains the substitution column.
     * 
     */
    public Optional<String> tableName() {
        return Optional.ofNullable(this.tableName);
    }
    /**
     * @return (Updatable) The type of the format entry.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return (Updatable) The user-defined function in SCHEMA_NAME.PACKAGE_NAME.FUNCTION_NAME format.  It can be a standalone or packaged function, so PACKAGE_NAME is optional.
     * 
     */
    public Optional<String> userDefinedFunction() {
        return Optional.ofNullable(this.userDefinedFunction);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(LibraryMasingFormatFormatEntry defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String columnName;
        private @Nullable String description;
        private @Nullable String endDate;
        private @Nullable Integer endLength;
        private @Nullable Double endValue;
        private @Nullable Double fixedNumber;
        private @Nullable String fixedString;
        private @Nullable List<String> groupingColumns;
        private @Nullable Integer length;
        private @Nullable String libraryMaskingFormatId;
        private @Nullable String pattern;
        private @Nullable String postProcessingFunction;
        private @Nullable List<String> randomLists;
        private @Nullable String regularExpression;
        private @Nullable String replaceWith;
        private @Nullable String schemaName;
        private @Nullable String sqlExpression;
        private @Nullable String startDate;
        private @Nullable Integer startLength;
        private @Nullable Integer startPosition;
        private @Nullable Double startValue;
        private @Nullable String tableName;
        private String type;
        private @Nullable String userDefinedFunction;
        public Builder() {}
        public Builder(LibraryMasingFormatFormatEntry defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.columnName = defaults.columnName;
    	      this.description = defaults.description;
    	      this.endDate = defaults.endDate;
    	      this.endLength = defaults.endLength;
    	      this.endValue = defaults.endValue;
    	      this.fixedNumber = defaults.fixedNumber;
    	      this.fixedString = defaults.fixedString;
    	      this.groupingColumns = defaults.groupingColumns;
    	      this.length = defaults.length;
    	      this.libraryMaskingFormatId = defaults.libraryMaskingFormatId;
    	      this.pattern = defaults.pattern;
    	      this.postProcessingFunction = defaults.postProcessingFunction;
    	      this.randomLists = defaults.randomLists;
    	      this.regularExpression = defaults.regularExpression;
    	      this.replaceWith = defaults.replaceWith;
    	      this.schemaName = defaults.schemaName;
    	      this.sqlExpression = defaults.sqlExpression;
    	      this.startDate = defaults.startDate;
    	      this.startLength = defaults.startLength;
    	      this.startPosition = defaults.startPosition;
    	      this.startValue = defaults.startValue;
    	      this.tableName = defaults.tableName;
    	      this.type = defaults.type;
    	      this.userDefinedFunction = defaults.userDefinedFunction;
        }

        @CustomType.Setter
        public Builder columnName(@Nullable String columnName) {

            this.columnName = columnName;
            return this;
        }
        @CustomType.Setter
        public Builder description(@Nullable String description) {

            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder endDate(@Nullable String endDate) {

            this.endDate = endDate;
            return this;
        }
        @CustomType.Setter
        public Builder endLength(@Nullable Integer endLength) {

            this.endLength = endLength;
            return this;
        }
        @CustomType.Setter
        public Builder endValue(@Nullable Double endValue) {

            this.endValue = endValue;
            return this;
        }
        @CustomType.Setter
        public Builder fixedNumber(@Nullable Double fixedNumber) {

            this.fixedNumber = fixedNumber;
            return this;
        }
        @CustomType.Setter
        public Builder fixedString(@Nullable String fixedString) {

            this.fixedString = fixedString;
            return this;
        }
        @CustomType.Setter
        public Builder groupingColumns(@Nullable List<String> groupingColumns) {

            this.groupingColumns = groupingColumns;
            return this;
        }
        public Builder groupingColumns(String... groupingColumns) {
            return groupingColumns(List.of(groupingColumns));
        }
        @CustomType.Setter
        public Builder length(@Nullable Integer length) {

            this.length = length;
            return this;
        }
        @CustomType.Setter
        public Builder libraryMaskingFormatId(@Nullable String libraryMaskingFormatId) {

            this.libraryMaskingFormatId = libraryMaskingFormatId;
            return this;
        }
        @CustomType.Setter
        public Builder pattern(@Nullable String pattern) {

            this.pattern = pattern;
            return this;
        }
        @CustomType.Setter
        public Builder postProcessingFunction(@Nullable String postProcessingFunction) {

            this.postProcessingFunction = postProcessingFunction;
            return this;
        }
        @CustomType.Setter
        public Builder randomLists(@Nullable List<String> randomLists) {

            this.randomLists = randomLists;
            return this;
        }
        public Builder randomLists(String... randomLists) {
            return randomLists(List.of(randomLists));
        }
        @CustomType.Setter
        public Builder regularExpression(@Nullable String regularExpression) {

            this.regularExpression = regularExpression;
            return this;
        }
        @CustomType.Setter
        public Builder replaceWith(@Nullable String replaceWith) {

            this.replaceWith = replaceWith;
            return this;
        }
        @CustomType.Setter
        public Builder schemaName(@Nullable String schemaName) {

            this.schemaName = schemaName;
            return this;
        }
        @CustomType.Setter
        public Builder sqlExpression(@Nullable String sqlExpression) {

            this.sqlExpression = sqlExpression;
            return this;
        }
        @CustomType.Setter
        public Builder startDate(@Nullable String startDate) {

            this.startDate = startDate;
            return this;
        }
        @CustomType.Setter
        public Builder startLength(@Nullable Integer startLength) {

            this.startLength = startLength;
            return this;
        }
        @CustomType.Setter
        public Builder startPosition(@Nullable Integer startPosition) {

            this.startPosition = startPosition;
            return this;
        }
        @CustomType.Setter
        public Builder startValue(@Nullable Double startValue) {

            this.startValue = startValue;
            return this;
        }
        @CustomType.Setter
        public Builder tableName(@Nullable String tableName) {

            this.tableName = tableName;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            if (type == null) {
              throw new MissingRequiredPropertyException("LibraryMasingFormatFormatEntry", "type");
            }
            this.type = type;
            return this;
        }
        @CustomType.Setter
        public Builder userDefinedFunction(@Nullable String userDefinedFunction) {

            this.userDefinedFunction = userDefinedFunction;
            return this;
        }
        public LibraryMasingFormatFormatEntry build() {
            final var _resultValue = new LibraryMasingFormatFormatEntry();
            _resultValue.columnName = columnName;
            _resultValue.description = description;
            _resultValue.endDate = endDate;
            _resultValue.endLength = endLength;
            _resultValue.endValue = endValue;
            _resultValue.fixedNumber = fixedNumber;
            _resultValue.fixedString = fixedString;
            _resultValue.groupingColumns = groupingColumns;
            _resultValue.length = length;
            _resultValue.libraryMaskingFormatId = libraryMaskingFormatId;
            _resultValue.pattern = pattern;
            _resultValue.postProcessingFunction = postProcessingFunction;
            _resultValue.randomLists = randomLists;
            _resultValue.regularExpression = regularExpression;
            _resultValue.replaceWith = replaceWith;
            _resultValue.schemaName = schemaName;
            _resultValue.sqlExpression = sqlExpression;
            _resultValue.startDate = startDate;
            _resultValue.startLength = startLength;
            _resultValue.startPosition = startPosition;
            _resultValue.startValue = startValue;
            _resultValue.tableName = tableName;
            _resultValue.type = type;
            _resultValue.userDefinedFunction = userDefinedFunction;
            return _resultValue;
        }
    }
}
