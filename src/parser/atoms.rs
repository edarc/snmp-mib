use nom::{
    branch::alt,
    bytes::complete::{is_not, tag},
    character::complete::{
        alpha1, alphanumeric1, char as the_char, digit1, hex_digit1, multispace0, multispace1,
        not_line_ending, one_of,
    },
    combinator::{eof, map, map_opt, opt, peek, recognize, value},
    multi::{many0, many1},
    sequence::{delimited, pair, terminated},
    IResult,
};
use num::Num;

/// Parse whitespace or comments and throw them away. Does *not* match zero length.
pub(crate) fn ws_or_comment(input: &str) -> IResult<&str, ()> {
    let white = || value((), multispace1);
    let comment = || value((), pair(tag("--"), not_line_ending));
    value((), alt((comment(), white())))(input)
}

/// Wrap a non-punctuation parser to eat trailing whitespace.
///
/// The entire parser is written with the invariant that whitespace and comments are always
/// stripped off the stream *after* each parsed item -- in other words, every parser leaves the
/// remaining string starting with something that is *not* whitespace or comment.
///
/// This whitespace eater is used for non-punctuation instead of `ptok` as it requires either some
/// amount of whitespace or comments (which it discards), or punctuation or EOF (which it does not
/// consume) after the token. This prevents the problem of `ptok(tag("FOO"))` successfully matching
/// `"FOObar"`, for example, when `FOO` is a keyword and `bar` is an identifier.
pub(crate) fn tok<'a, F, O>(inner: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: FnMut(&'a str) -> IResult<&'a str, O>,
{
    let punc = value((), peek(one_of(".,;:()[]{}<>=|")));
    let end = value((), eof);
    let del = alt((value((), many1(ws_or_comment)), punc, end));
    terminated(inner, del)
}

pub(crate) fn kw(word: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input| tok(tag(word))(input)
}

/// Wrap a punctuation parser to eat trailing whitespace.
///
/// The entire parser is written with the invariant that whitespace and comments are always
/// stripped off the stream *after* each parsed item -- in other words, every parser leaves the
/// remaining string starting with something that is *not* whitespace or comment.
///
/// This whitespace eater is used for punctuation instead of `tok` as it will accept zero-length
/// whitespace or comments after the token.
pub(crate) fn ptok<'a, F, O>(inner: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: FnMut(&'a str) -> IResult<&'a str, O>,
{
    terminated(inner, many0(ws_or_comment))
}

/// Parse a MIB identifier.
pub(crate) fn identifier(input: &str) -> IResult<&str, &str> {
    tok(recognize(pair(
        alpha1,
        many0(alt((alphanumeric1, tag("-")))),
    )))(input)
}

pub(crate) fn sym(sym: &'static str) -> impl Fn(&str) -> IResult<&str, &str> {
    move |input| ptok(tag(sym))(input)
}

/// Parse a double-quoted string.
///
/// String may potentially span many lines, as is common in MIB definitions. Does not currently
/// support escaped close-quote.
pub(crate) fn quoted_string(input: &str) -> IResult<&str, &str> {
    delimited(
        tag("\""),
        map(opt(is_not("\"")), |s| s.unwrap_or("")),
        tok(tag("\"")),
    )(input)
}

pub(crate) fn signed<T>(input: &str) -> IResult<&str, T>
where
    T: Num,
{
    let dec = tok(recognize(pair(tag("-"), digit1)));
    alt((map_opt(dec, |t| T::from_str_radix(t, 10).ok()), unsigned))(input)
}

pub(crate) fn unsigned<T>(input: &str) -> IResult<&str, T>
where
    T: Num,
{
    let dec = map_opt(digit1, |t| T::from_str_radix(t, 10).ok());
    let hex = map_opt(
        delimited(
            tag("'"),
            many1(delimited(multispace0, hex_digit1, multispace0)),
            pair(the_char('\''), one_of("Hh")),
        ),
        |t| T::from_str_radix(&t.join(""), 16).ok(),
    );
    let bin = map_opt(
        delimited(
            tag("'"),
            many1(delimited(multispace0, one_of("01"), multispace0)),
            pair(the_char('\''), one_of("Bb")),
        ),
        |t| T::from_str_radix(&t.into_iter().collect::<String>(), 2).ok(),
    );
    tok(alt((dec, hex, bin)))(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! parse_ok {
        ($parser:expr, $case:literal, $val:expr) => {
            assert_eq!($parser($case), Ok(("", $val)))
        };
    }

    macro_rules! parse_fail {
        ($parser:expr, $case:literal) => {
            assert!($parser($case).is_err())
        };
    }

    #[test]
    fn signed_number() {
        parse_ok!(signed::<u8>, "123", 123);
        parse_ok!(signed::<i8>, "-123", -123);

        parse_ok!(signed, "'ff'h", 255);
        parse_ok!(signed, "'1100'b", 0xC);

        parse_ok!(signed, "'01 ff'h", 0x1FF);
        parse_ok!(signed, "'0001 1111'b", 0x1F);

        parse_ok!(signed, "'  01 ff 'h", 0x1FF);
        parse_ok!(signed, "'   0001 1111 'b", 0x1F);
    }

    #[test]
    fn unsigned_number() {
        parse_ok!(unsigned::<u8>, "123", 123);
        parse_fail!(unsigned::<u8>, "-123");

        parse_ok!(unsigned, "'ff'h", 255);
        parse_ok!(unsigned, "'1100'b", 0xC);

        parse_ok!(unsigned, "'01 ff'h", 0x1FF);
        parse_ok!(unsigned, "'0001 1111'b", 0x1F);

        parse_ok!(unsigned, "'  01 ff 'h", 0x1FF);
        parse_ok!(unsigned, "'   0001 1111 'b", 0x1F);
    }
}
