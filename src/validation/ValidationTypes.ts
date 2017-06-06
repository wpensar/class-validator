import {ValidationArguments} from "./ValidationArguments";

/**
 * Validation types.
 */
export class ValidationTypes {
    
    /* system */
    static CUSTOM_VALIDATION = "customValidation";
    static NESTED_VALIDATION = "nestedValidation";
    static CONDITIONAL_VALIDATION = "conditionalValidation";

    /* common checkers */
    static IS_DEFINED = "isDefined";
    static EQUALS = "equals";
    static NOT_EQUALS = "notEquals";
    static IS_EMPTY = "isEmpty";
    static IS_NOT_EMPTY = "isNotEmpty";
    static IS_IN = "isIn";
    static IS_NOT_IN = "isNotIn";

    /* type checkers */
    static IS_BOOLEAN = "isBoolean";
    static IS_DATE = "isDate";
    static IS_NUMBER = "isNumber";
    static IS_STRING = "isString";
    static IS_ARRAY = "isArray";
    static IS_INT = "isInt";
    static IS_ENUM = "isEnum";

    /* number checkers */
    static IS_DIVISIBLE_BY = "isDivisibleBy";
    static IS_POSITIVE = "isPositive";
    static IS_NEGATIVE = "isNegative";
    static MIN = "min";
    static MAX = "max";

    /* date checkers */
    static MIN_DATE = "minDate";
    static MAX_DATE = "maxDate";

    /* string-as-type checkers */
    static IS_BOOLEAN_STRING = "isBooleanString";
    static IS_NUMBER_STRING = "isNumberString";

    /* string checkers */
    static CONTAINS = "contains";
    static NOT_CONTAINS = "notContains";
    static IS_ALPHA = "isAlpha";
    static IS_ALPHANUMERIC = "isAlphanumeric";
    static IS_ASCII = "isAscii";
    static IS_BASE64 = "isBase64";
    static IS_BYTE_LENGTH = "isByteLength";
    static IS_CREDIT_CARD = "isCreditCard";
    static IS_CURRENCY = "isCurrency";
    static IS_EMAIL = "isEmail";
    static IS_FQDN = "isFqdn";
    static IS_FULL_WIDTH = "isFullWidth";
    static IS_HALF_WIDTH = "isHalfWidth";
    static IS_VARIABLE_WIDTH = "isVariableWidth";
    static IS_HEX_COLOR = "isHexColor";
    static IS_HEXADECIMAL = "isHexadecimal";
    static IS_IP = "isIp";
    static IS_ISBN = "isIsbn";
    static IS_ISIN = "isIsin";
    static IS_ISO8601 = "isIso8601";
    static IS_JSON = "isJson";
    static IS_LOWERCASE = "isLowercase";
    static IS_MOBILE_PHONE = "isMobilePhone";
    static IS_MONGO_ID = "isMongoId";
    static IS_MULTIBYTE = "isMultibyte";
    static IS_SURROGATE_PAIR = "isSurrogatePair";
    static IS_URL = "isUrl";
    static IS_UUID = "isUuid";
    static LENGTH = "length";
    static IS_UPPERCASE = "isUppercase";
    static MIN_LENGTH = "minLength";
    static MAX_LENGTH = "maxLength";
    static MATCHES = "matches";
    static IS_MILITARY_TIME = "isMilitaryTime";

    /* array checkers */
    static ARRAY_CONTAINS = "arrayContains";
    static ARRAY_NOT_CONTAINS = "arrayNotContains";
    static ARRAY_NOT_EMPTY = "arrayNotEmpty";
    static ARRAY_MIN_SIZE = "arrayMinSize";
    static ARRAY_MAX_SIZE = "arrayMaxSize";
    static ARRAY_UNIQUE = "arrayUnique";

    /**
     * Checks if validation type is valid.
     */
    static isValid(type: string) {
        return  type !== "isValid" &&
                type !== "getMessage" &&
                Object.keys(this).map(key => (this as any)[key]).indexOf(type) !== -1;
    }

    /**
     * Gets default validation error message for the given validation type.
     */
    static getMessage(type: string, isEach: boolean): string|((args: ValidationArguments) => string) {
        const eachPrefix = isEach ? "each value in " : "";
        switch (type) {

            /* common checkers */
            case this.IS_DEFINED:
                return eachPrefix + "$property não deveria ser vazio";
            case this.EQUALS:
                return eachPrefix + "$property deve ser igual a $constraint1";
            case this.NOT_EQUALS:
                return eachPrefix + "$property não deveria ser igual a $constraint1";
            case this.IS_EMPTY:
                return eachPrefix + "$property deve ser vazio";
            case this.IS_NOT_EMPTY:
                return eachPrefix + "$property não deveria ser vazio";
            case this.IS_IN:
                return eachPrefix + "$property deve ser um dos seguintes valores: $constraint1";
            case this.IS_NOT_IN:
                return eachPrefix + "$property não deveria ser one dos seguintes valores: $constraint1";

            /* type checkers */
            case this.IS_BOOLEAN:
                return eachPrefix + "$property deve ser um booleano";
            case this.IS_DATE:
                return eachPrefix + "$property deve ser uma data";
            case this.IS_NUMBER:
                return eachPrefix + "$property deve ser um número";
            case this.IS_INT:
                return eachPrefix + "$property deve ser um número inteiro";
            case this.IS_STRING:
                return eachPrefix + "$property deve ser um texto";
            case this.IS_ARRAY:
                return eachPrefix + "$property deve ser uma lista";
            case this.IS_ENUM:
                return eachPrefix + "$property deve ser um enumerador";

            /* number checkers */
            case this.IS_DIVISIBLE_BY:
                return eachPrefix + "$property deve ser divisible by $constraint1";
            case this.IS_POSITIVE:
                return eachPrefix + "$property deve ser um número positivo";
            case this.IS_NEGATIVE:
                return eachPrefix + "$property deve ser um número negativo";
            case this.MIN:
                return eachPrefix + "$property deve ser maior que $constraint1";
            case this.MAX:
                return eachPrefix + "$property deve ser menor que $constraint1";

            /* date checkers */
            case this.MIN_DATE:
                return "data mínima permitida para " + eachPrefix + "$property é $constraint1";
            case this.MAX_DATE:
                return "data máxima permitida para " + eachPrefix + "$property é $constraint1";

            /* string-as-type checkers */
            case this.IS_BOOLEAN_STRING:
                return eachPrefix + "$property deve ser um texto booleano";
            case this.IS_NUMBER_STRING:
                return eachPrefix + "$property deve ser um texto somente de números";

            /* string checkers */
            case this.CONTAINS:
                return eachPrefix + "$property deve conter um $constraint1 texto";
            case this.NOT_CONTAINS:
                return eachPrefix + "$property não deveria conter um $constraint1 texto";
            case this.IS_ALPHA:
                return eachPrefix + "$property deve conter somente letras (a-zA-Z)";
            case this.IS_ALPHANUMERIC:
                return eachPrefix + "$property deve conter somente letras and numbers";
            case this.IS_ASCII:
                return eachPrefix + "$property deve conter somente ASCII caracteres";
            case this.IS_BASE64:
                return eachPrefix + "$property deve ser base64 encoded";
            case this.IS_BYTE_LENGTH:
                return eachPrefix + "$property's byte length must fall into ($constraint1, $constraint2) range";
            case this.IS_CREDIT_CARD:
                return eachPrefix + "$property deve ser um formato de cartão de crédito";
            case this.IS_CURRENCY:
                return eachPrefix + "$property deve ser um valor monetário";
            case this.IS_EMAIL:
                return eachPrefix + "$property deve ser um email";
            case this.IS_FQDN:
                return eachPrefix + "$property deve ser um nome de domínio válido";
            case this.IS_FULL_WIDTH:
                return eachPrefix + "$property deve ser totalmente preenchido";
            case this.IS_HALF_WIDTH:
                return eachPrefix + "$property deve ser parcialmente preenchido";
            case this.IS_VARIABLE_WIDTH:
                return eachPrefix + "$property pode ser parcialmente preenchido";
            case this.IS_HEX_COLOR:
                return eachPrefix + "$property deve ser uma cor hexadecimal";
            case this.IS_HEXADECIMAL:
                return eachPrefix + "$property deve ser um número hexadecimal";
            case this.IS_IP:
                return eachPrefix + "$property deve ser um endereço de IP";
            case this.IS_ISBN:
                return eachPrefix + "$property deve ser um ISBN";
            case this.IS_ISIN:
                return eachPrefix + "$property deve ser um ISIN (stock/security identifier)";
            case this.IS_ISO8601:
                return eachPrefix + "$property deve ser uma data válida";
            case this.IS_JSON:
                return eachPrefix + "$property deve ser um json string";
            case this.IS_LOWERCASE:
                return eachPrefix + "$property deve possuir todos as letras minúsculas";
            case this.IS_MOBILE_PHONE:
                return eachPrefix + "$property deve ser um telefone";
            case this.IS_MONGO_ID:
                return eachPrefix + "$property deve ser um mongodb id";
            case this.IS_MULTIBYTE:
                return eachPrefix + "$property deve conter um ou mais multibytes";
            case this.IS_SURROGATE_PAIR:
                return eachPrefix + "$property deve conter qualquer par substituto de caracteres";
            case this.IS_URL:
                return eachPrefix + "$property deve ser uma URL";
            case this.IS_UUID:
                return eachPrefix + "$property deve ser um UUID";
            case this.IS_UPPERCASE:
                return eachPrefix + "$property deve possuir todos os caracteres maiúsculos";
            case this.LENGTH:
                return (args: ValidationArguments) => {
                    const isMinLength = args.constraints[0] !== null && args.constraints[0] !== undefined;
                    const isMaxLength = args.constraints[1] !== null && args.constraints[1] !== undefined;
                    if (isMinLength && (!args.value || args.value.length < args.constraints[0])) {
                        return eachPrefix + "$property deve maior que $constraint1";
                    } else if (isMaxLength && (args.value.length > args.constraints[1])) {
                        return eachPrefix + "$property deve ser menor que $constraint2";
                    }
                    return eachPrefix + "$property deve ser maior que $constraint1 e menor que $constraint2";
                };
            case this.MIN_LENGTH:
                return eachPrefix + "$property deve maior que $constraint1";
            case this.MAX_LENGTH:
                return eachPrefix + "$property deve ser menor que $constraint1";
            case this.MATCHES:
                return eachPrefix + "$property deve ser encontra para expressão regular($constraint1)";

            /* array checkers */
            case this.ARRAY_CONTAINS:
                return eachPrefix + "$property deve conter os valores $constraint1";
            case this.ARRAY_NOT_CONTAINS:
                return eachPrefix + "$property não deve conter os valores $constraint1";
            case this.ARRAY_NOT_EMPTY:
                return eachPrefix + "$property não deveria estar vazio";
            case this.ARRAY_MIN_SIZE:
                return eachPrefix + "$property deve conter ao menos $constraint1 elementos";
            case this.ARRAY_MAX_SIZE:
                return eachPrefix + "$property não deve conter mais de $constraint1 elementos";
            case this.ARRAY_UNIQUE:
                return eachPrefix + "Todos os elementos devem únicos";
        }
        
        return "";
    }
    
}
